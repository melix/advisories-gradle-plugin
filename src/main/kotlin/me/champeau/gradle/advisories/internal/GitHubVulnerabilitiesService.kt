package me.champeau.gradle.advisories.internal

import com.fasterxml.jackson.databind.JsonNode
import io.github.rybalkinsd.kohttp.dsl.httpPost
import io.github.rybalkinsd.kohttp.jackson.ext.toJson
import me.champeau.gradle.advisories.*
import okhttp3.Response

class GitHubVulnerabilitiesService(val accessToken: String) : VulnerabilitiesService {

    companion object {
        const val TEMPLATE = "query {" +
                "  securityVulnerabilities(ecosystem: MAVEN, package:\"%PACKAGE%\", orderBy:{field: UPDATED_AT, direction: DESC}, first: 100) {\n" +
                "    nodes {\n" +
                "      severity\n" +
                "      vulnerableVersionRange\n" +
                "      firstPatchedVersion {\n" +
                "        identifier\n" +
                "      }\n" +
                "      advisory {\n" +
                "        identifiers { value }\n" +
                "        summary\n" +
                "        description\n" +
                "      }\n" +
                "    }\n" +
                "  } }"
    }

    override fun vulnerabilitiesFor(module: String): ModuleVulnerabilities {
        val response: Response = httpPost {
            host = "api.github.com"
            path = "/graphql"
            scheme = "https"

            header {
                "Authorization" to "bearer $accessToken"
            }

            body {
                json {
                    val text = query(module)
                    "query" to text
                }
            }
        }
        val json = response.toJson()
        return ModuleVulnerabilities(System.currentTimeMillis(), toVulnerabilities(json))
    }

    private
    fun toVulnerabilities(json: JsonNode): List<Vulnerability> = json["data"]["securityVulnerabilities"]["nodes"].map {
        val advisory = it["advisory"]
        val (lower, upper) = parseVersionRange(
                it["vulnerableVersionRange"].asText()
        )
        Vulnerability(
                advisory["identifiers"].map { it["value"].asText() },
                Severity.valueOf(it["severity"].asText()),
                it["firstPatchedVersion"]?.get("identifier")?.asText(),
                lower,
                upper,
                advisory["summary"].asText(),
                advisory["description"].asText())

    }

    private fun parseVersionRange(range: String): Pair<Version?, Version?> {
        var lower: Version? = null
        var upper: Version? = null
        if (range.startsWith(">")) {
            val include = range[1] == '='
            val comma = range.indexOf(",")
            if (include) {
                lower = Version(
                        range.substring(3, comma),
                        true
                )
            } else {
                lower = Version(
                        range.substring(2, comma),
                        false
                )
            }
        }
        val idx = range.indexOf("<")
        if (idx > 0) {
            val include = range[idx + 1] == '='
            if (include) {
                upper = Version(
                        range.substring(idx + 3),
                        true
                )
            } else {
                upper = Version(
                        range.substring(idx + 2),
                        false
                )
            }
        }
        return Pair(lower, upper)
    }

    private
    fun query(pkg: String): String =
            TEMPLATE.replace("%PACKAGE%", pkg)
                    .replace("\n", " ")
                    .replace("\"", "\\\"")
}
