package me.champeau.gradle.advisories.internal

import me.champeau.gradle.advisories.ModuleVulnerabilities
import me.champeau.gradle.advisories.VulnerabilitiesService
import java.util.concurrent.ConcurrentHashMap

class InMemoryCachingVulnerabilitiesService(
        val delegate: VulnerabilitiesService,
        val cache: MutableMap<String, ModuleVulnerabilities> = ConcurrentHashMap()
): VulnerabilitiesService {
    override fun vulnerabilitiesFor(module: String): ModuleVulnerabilities =
            cache.getOrPut(module) { delegate.vulnerabilitiesFor(module) }

}