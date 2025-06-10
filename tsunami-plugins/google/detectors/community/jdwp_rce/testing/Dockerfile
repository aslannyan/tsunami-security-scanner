# Use a simple Java base image
FROM eclipse-temurin:11-jre-focal

# Set a working directory
WORKDIR /app

# Create a simple "Hello World" Java application that runs indefinitely
# and listens for JDWP on port 5005.
RUN echo 'public class HelloWorld {
    public static void main(String[] args) throws InterruptedException {
        System.out.println("Hello World JDWP Test Application Running...");
        System.out.println("JDWP agent configured on port 5005.");
        // Keep the application running indefinitely
        while(true) {
            Thread.sleep(10000);
        }
    }
}' > HelloWorld.java

# Compile the Java application
RUN javac HelloWorld.java

# Expose the JDWP port
EXPOSE 5005

# Command to run the Java app with JDWP agent enabled and listening on all interfaces
# suspend=n means the JVM starts immediately without waiting for a debugger to attach.
# address=*:5005 means listen on port 5005 on all available network interfaces.
CMD ["java", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005", "HelloWorld"]
