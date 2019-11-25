package me.champeau.gradle.advisories

interface VulnerabilitiesService {
    fun vulnerabilitiesFor(module: String): ModuleVulnerabilities
}