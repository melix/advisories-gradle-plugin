package me.champeau.gradle.advisories

import kotlinx.serialization.Serializable

@Serializable
data class ModuleVulnerabilities(
        val timestamp: Long,
        val vulnerabilities: List<Vulnerability>
) {
    fun hasVulnerabilities() = vulnerabilities.isNotEmpty()

    fun findVulnerabilitiesForVersion(version: String) = vulnerabilities.filter {
        it.appliesTo(version)
    }

}