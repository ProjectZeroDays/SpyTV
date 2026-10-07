plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.authenticated.spytv"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.authenticated.spytv"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        // Enable Java 17 features
        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_17
            targetCompatibility = JavaVersion.VERSION_17
        }
        
        kotlinOptions {
            jvmTarget = "17"
        }
        
        buildFeatures {
            viewBinding = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Sideloaded operator console, not a store listing: sign with the
            // local debug keystore so the APK is installable without putting
            // signing secrets in the repo. Stable per machine, so upgrades
            // over an existing install keep working.
            signingConfig = signingConfigs.getByName("debug")
        }
        
        debug {
            // Enable debugging for standalone C2 mode
            debuggable = true
            jniDebuggable = true
        }
    }
    
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    
    kotlinOptions {
        jvmTarget = "17"
    }
    
    buildFeatures {
        viewBinding = true
    }
    
    // Allow network security config
    packagingOptions {
        jss {
            // Keep stdlib
            exclude("META-INF/AL2.0", "META-INF/LGPL2.1")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    
    // JSON support - org.json is built-in but we add this for convenience
    implementation("org.json:json:20240303")
    
    // For standalone C2 mode, we need Java HTTP server (built-in via Android API)
    // No additional dependency needed for com.sun.net.httpserver
}