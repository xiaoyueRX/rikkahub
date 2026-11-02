package me.rerere.workspace.ssh

import me.rerere.workspace.WorkspaceStorageArea
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.PasswordAuthenticator
import org.apache.sshd.server.forward.AcceptAllForwardingFilter
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider
import org.apache.sshd.sftp.server.SftpSubsystemFactory
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.net.ServerSocket
import java.util.Base64
import kotlin.concurrent.thread

/**
 * 跳板机 (ProxyJump) 连接: 双嵌入式 SSH 服务器 (跳板 + 目标), 验证
 * 指纹独立确认、隧道收发、凭据不泄漏与卡死时的看门狗返回。
 */
class SshJumpHostTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var jumpServer: SshServer
    private lateinit var targetServer: SshServer
    private lateinit var remoteDir: java.io.File
    private lateinit var home: java.io.File
    private val pool = SshConnectionPool()

    @Before
    fun setUp() {
        remoteDir = tempFolder.newFolder("remote").canonicalFile
        home = tempFolder.newFolder("home").canonicalFile
        jumpServer = SshServer.setUpDefaultServer().apply {
            host = "127.0.0.1"
            port = 0
            keyPairProvider = SimpleGeneratorHostKeyProvider(File(tempFolder.root, "jump_host_key").toPath())
            passwordAuthenticator = PasswordAuthenticator { username, password, _ ->
                username == JUMP_USER && password == JUMP_PASSWORD
            }
            // 跳板只负责 direct-tcpip 转发
            forwardingFilter = AcceptAllForwardingFilter.INSTANCE
            start()
        }
        targetServer = SshServer.setUpDefaultServer().apply {
            host = "127.0.0.1"
            port = 0
            keyPairProvider = SimpleGeneratorHostKeyProvider(File(tempFolder.root, "target_host_key").toPath())
            passwordAuthenticator = PasswordAuthenticator { username, password, _ ->
                username == USER && password == PASSWORD
            }
            subsystemFactories = listOf(SftpSubsystemFactory())
            commandFactory = org.apache.sshd.server.command.CommandFactory { channel, command ->
                org.apache.sshd.server.shell.ProcessShellFactory(
                    command,
                    "/usr/bin/env",
                    "HOME=${home.path}",
                    "SHELL=/bin/sh",
                    "/bin/sh",
                    "-c",
                    command,
                ).createShell(channel)
            }
            start()
        }
    }

    @After
    fun tearDown() {
        pool.close()
        targetServer.stop(true)
        jumpServer.stop(true)
    }

    private fun jumpConfig(hostKey: SshHostKey? = null) = SshJumpConfig(
        host = "127.0.0.1",
        port = jumpServer.port,
        username = JUMP_USER,
        authType = SshAuthType.PASSWORD,
        password = JUMP_PASSWORD,
        hostKey = hostKey,
    )

    private fun targetConfig(jump: SshJumpConfig?, hostKey: SshHostKey? = null) = SshConnectionConfig(
        host = "127.0.0.1",
        port = targetServer.port,
        username = USER,
        authType = SshAuthType.PASSWORD,
        password = PASSWORD,
        remoteDir = remoteDir.path,
        hostKey = hostKey,
        jump = jump,
    )

    private fun trustedJump(): SshJumpConfig {
        val hostKey = assertThrows(SshUnknownHostKeyException::class.java) {
            pool.probe(targetConfig(jump = jumpConfig()))
        }.hostKey
        return jumpConfig(hostKey)
    }

    private fun trustedTarget(jump: SshJumpConfig): SshConnectionConfig {
        val hostKey = assertThrows(SshUnknownHostKeyException::class.java) {
            pool.probe(targetConfig(jump = jump))
        }.hostKey
        return targetConfig(jump = jump, hostKey = hostKey)
    }

    @Test
    fun unknownJumpHostKeyIsFlagged() {
        val error = assertThrows(SshUnknownHostKeyException::class.java) {
            pool.probe(targetConfig(jump = jumpConfig()))
        }
        assertTrue(error.isJumpHost)
        assertTrue(error.hostKey.fingerprint.startsWith("SHA256:"))
    }

    @Test
    fun probeAndFileOperationsGoThroughJump() {
        val jump = trustedJump()
        val config = trustedTarget(jump)
        val result = pool.probe(config)
        assertTrue(result.remoteDirExists)
        assertTrue(result.shell.startsWith("/"))

        val backend = SshWorkspaceBackend(pool, WORKSPACE_ID, config)
        backend.writeText("jump.txt", "hello via jump", overwrite = true)
        assertEquals("hello via jump", backend.readText("jump.txt"))
        assertTrue(backend.listFiles(WorkspaceStorageArea.FILES, ".").any { it.name == "jump.txt" })
    }

    @Test
    fun targetHostKeyIsStillEnforcedThroughJump() {
        val jump = trustedJump()
        val forged = SshHostKey(type = "ssh-ed25519", key = Base64.getEncoder().encodeToString(ByteArray(51) { 2 }))
        val error = assertThrows(SshHostKeyChangedException::class.java) {
            pool.probe(targetConfig(jump = jump, hostKey = forged))
        }
        assertFalse(error.isJumpHost)
        assertEquals(forged, error.expected)
    }

    @Test
    fun changedJumpHostKeyIsFlagged() {
        val jump = trustedJump()
        val forged = SshHostKey(type = "ssh-ed25519", key = Base64.getEncoder().encodeToString(ByteArray(51) { 3 }))
        val error = assertThrows(SshHostKeyChangedException::class.java) {
            pool.probe(targetConfig(jump = jump.copy(hostKey = forged)))
        }
        assertTrue(error.isJumpHost)
    }

    @Test
    fun wrongJumpPasswordFailsWithoutLeakingCredentials() {
        val jump = trustedJump()
        val error = assertThrows(IOException::class.java) {
            pool.probe(targetConfig(jump = jump.copy(password = "wrong")))
        }
        assertFalse(error.message!!.contains("wrong"))
        assertFalse(error.message!!.contains(PASSWORD))
    }

    @Test
    fun deadTargetPortBehindJumpFailsFast() {
        val jump = trustedJump()
        // 端口占住但不回 banner: direct-tcpip 能开, 目标握手卡死, 看门狗必须按时返回
        ServerSocket(0).use { sink ->
            thread(isDaemon = true) { runCatching { sink.accept() } }
            val start = System.currentTimeMillis()
            val error = assertThrows(Exception::class.java) {
                SshConnection.open(targetConfig(jump = jump).copy(port = sink.localPort))
            }
            val elapsed = System.currentTimeMillis() - start
            assertTrue("open returned too late (${elapsed}ms): $error", elapsed < 45_000)
        }
    }

    @Test
    fun poolReuseDistinguishesJumpConfigs() {
        val direct = targetConfig(jump = null)
        val viaJump = targetConfig(jump = jumpConfig())
        assertEquals(direct, direct.copy())
        assertFalse("同目标不同 jump 必须视为不同配置", direct == viaJump)
        assertTrue(viaJump == viaJump.copy(jump = jumpConfig()))
    }

    private companion object {
        const val USER = "rikkatest"
        const val PASSWORD = "rikkatest-pw"
        const val JUMP_USER = "jumpuser"
        const val JUMP_PASSWORD = "jump-pw"
        const val WORKSPACE_ID = "jump-test-workspace"
    }
}
