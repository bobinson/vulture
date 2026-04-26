plugins {
    scala
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.scala-lang:scala3-library_3:3.3.3")
    implementation("com.google.code.gson:gson:2.11.0")
}

application {
    mainClass.set("OracleCLI")
}

tasks.jar {
    manifest {
        attributes("Main-Class" to "OracleCLI")
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}
