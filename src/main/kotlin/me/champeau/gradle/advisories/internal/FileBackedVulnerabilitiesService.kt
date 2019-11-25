package me.champeau.gradle.advisories.internal

import kotlinx.serialization.cbor.Cbor
import me.champeau.gradle.advisories.ModuleVulnerabilities
import me.champeau.gradle.advisories.VulnerabilitiesService
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

class FileBackedVulnerabilitiesService(
        val timeout: Long,
        val unit: TimeUnit,
        val store: Path,
        val delegate: VulnerabilitiesService
        ): VulnerabilitiesService {

    override
    fun vulnerabilitiesFor(module: String): ModuleVulnerabilities = store.resolve(dirName(module)).run {
        val binFile = resolve("vulnerabilities.bin")
        if (Files.exists(this)) {
            val contents = Files.readAllBytes(binFile)
            val serialized = Cbor.load(ModuleVulnerabilities.serializer(), contents)
            if (!timedOut(serialized)) {
                return serialized
            }
        }
        val out = delegate.vulnerabilitiesFor(module)
        Files.createDirectories(this)
        Files.write(binFile, Cbor.dump(ModuleVulnerabilities.serializer(), out))
        return out
    }

    private fun dirName(module: String) =
            module.replace(":", File.separator)

    private fun timedOut(vulnerabilities: ModuleVulnerabilities) =
            (System.currentTimeMillis() - vulnerabilities.timestamp) > TimeUnit.MILLISECONDS.convert(timeout, unit)
}