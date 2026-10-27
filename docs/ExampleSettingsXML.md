# Maven Settings XML file example.
This is very basic template. For more complex settings take a look at: [Official maven docs](https://maven.apache.org/settings.html)
```xml

<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                      http://maven.apache.org/xsd/settings-1.0.0.xsd">

  <activeProfiles>
    <activeProfile>my-github</activeProfile>
  </activeProfiles>

  <profiles>
    <profile>
      <id>my-github</id>
      <repositories>
          
        <repository>
          <id>gh-ys-j-autocrypt</id>
          <url>https://maven.pkg.github.com/Ysdaeth/j-autocrypt</url>
        </repository>
          
        <!-- maven repository -->
        <repository>
          <id>central</id>
          <url>https://repo.maven.apache.org/maven2</url>
        </repository>
          
      </repositories>
    </profile>
  </profiles>

  <servers>
    <server>
      <id>gh-ys-j-autocrypt</id>
      <username>YOUR_USERNAME</username>
      <password>TOKEN</password>
    </server>
  </servers>

</settings>
```