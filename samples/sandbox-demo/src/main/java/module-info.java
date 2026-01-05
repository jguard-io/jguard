module org.jguard.samples.sandbox {
    requires org.jguard.core;
    requires java.net.http;

    exports org.jguard.samples.sandbox;
    exports org.jguard.samples.sandbox.net;
    exports org.jguard.samples.sandbox.net.restricted;
    exports org.jguard.samples.sandbox.worker;
}
