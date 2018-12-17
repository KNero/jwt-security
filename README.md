# jwt-security
# Maven
```xml
<repositories>
    <repository>
        <id>exof-maven</id>
        <url>https://github.com/KNero/repository/raw/master/maven</url>
    </repository>
</repositories>
```
```xml
<dependency>
    <groupId>team.balam</groupId>
    <artifactId>jwt-security</artifactId>
    <version>0.0.1</version>
</dependency>
```
# Gradle
```gradle
repositories {
    maven {
        mavenLocal()
        maven {
            url "https://github.com/KNero/repository/raw/master/maven"
        }
    }
}
```
```gradle
dependencies {
    compile 'team.balam:jwt-security:0.0.1'
}
```
