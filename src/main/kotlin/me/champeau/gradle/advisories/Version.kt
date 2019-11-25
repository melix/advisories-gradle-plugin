package me.champeau.gradle.advisories
import kotlinx.serialization.Serializable

@Serializable
data class Version (val name: String, val included: Boolean)
