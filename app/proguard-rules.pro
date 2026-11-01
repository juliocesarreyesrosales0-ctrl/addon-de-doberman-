# La app no usa reflexión sobre sus propias clases; R8 puede optimizar libremente.
# Se conservan los nombres de los componentes declarados en el manifiesto (R8 lo hace por defecto).
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
