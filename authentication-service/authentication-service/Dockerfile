FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace

COPY gradlew gradlew.bat settings.gradle.kts build.gradle.kts ./
COPY gradle ./gradle
COPY src ./src

RUN chmod +x ./gradlew
RUN ./gradlew clean bootJar --no-daemon

FROM eclipse-temurin:21-jre
WORKDIR /app

RUN groupadd --system codeforge && useradd --system --gid codeforge codeforge

COPY --from=build /workspace/build/libs/*.jar /app/authentication-service.jar

EXPOSE 8081
USER codeforge

ENTRYPOINT ["java", "-jar", "/app/authentication-service.jar"]
