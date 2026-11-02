plugins {
    kotlin("jvm") version "2.2.10"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.17.0")
}

kotlin {
    sourceSets["main"].kotlin.srcDir("../../../../build/bindings/kotlin")
}

application {
    mainClass.set("dev.hewig.railgun.smoke.MainKt")
    applicationDefaultJvmArgs = listOf("-Djna.library.path=${rootDir.resolve("../../../../target/release").canonicalPath}")
}
