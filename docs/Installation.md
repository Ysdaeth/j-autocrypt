# How to install
Packages are available do download with GitHub package repository, but not with Maven Repository - at least not yet.  

  
## Two ways to install.

### Download with GitHub packages
1. Go to `.m2/settings.xml` file and add repository. If there is no such file, create one. [Example settings.xml file](ExampleSettingsXML.md)
```xml
<repository>
    <id>gh-ys-j-autocrypt</id>
    <url>https://maven.pkg.github.com/Ysdaeth/j-autocrypt</url>
</repository>
```

### Alternatively, download repository and install locally
```shell
git clone https://github.com/Ysdaeth/j-autocrypt.git
cd j-autocrypt
sudo mvn clean install
```