# ---------- FASE 1: BUILD ----------
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app

# Copiar solo lo necesario para descargar dependencias
COPY gradle gradle
COPY gradlew .
COPY build.gradle.kts settings.gradle.kts ./

# Dar permisos a gradlew
RUN chmod +x gradlew

# Descargar dependencias
RUN ./gradlew dependencies

# Copiar todo el proyecto
COPY . .

# Dar permisos otra vez a gradlew
RUN chmod +x gradlew

# Compilar JAR
RUN ./gradlew clean build -x test

# ---------- FASE 2: RUNTIME ----------
FROM eclipse-temurin:21-jre
WORKDIR /app

# Crear usuario para ejecutar app
RUN useradd -m ktor
USER ktor

# Copiar el JAR final desde la build
COPY --from=build /app/build/libs/*.jar app.jar

# Exponer puerto
EXPOSE 8080

# CMD correcto para ejecutar el JAR
CMD ["java", "-jar", "app.jar"]
