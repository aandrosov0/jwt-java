# JWT (JSON WEB TOKEN) implementation written in Java Language


To get a Git project into your build:

**Step 1**. Add the JitPack repository to your build file 
```groovy
	allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
```

**Step 2**. Add the dependency

```groovy
	dependencies {
	        implementation 'com.github.aandrosov0:jwt-java:master-SNAPSHOT'
	}
```

See our [WIKI](https://github.com/aandrosov0/jwt-java/wiki) to learn about JWT.
