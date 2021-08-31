FROM openjdk:11-jre-slim

ADD target/user-service-0.0.1-SNAPSHOT.jar /app.jar

CMD ["java", "-jar", "/app.jar"]