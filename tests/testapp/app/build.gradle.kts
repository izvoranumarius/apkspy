plugins { id("com.android.application") }
android {
    namespace = "com.example.apkspytestapp"
    compileSdk = 34
    defaultConfig { minSdk = 24 }
    buildTypes.getByName("release") { isMinifyEnabled = false }
    buildFeatures { buildConfig = false }
}
// Plain android.* APIs only: no dependencies on purpose.
