module io.jguard.samples.sandbox {
    requires io.jguard.core;
    requires java.net.http;

    exports io.jguard.samples.sandbox;
    exports io.jguard.samples.sandbox.net;
    exports io.jguard.samples.sandbox.net.restricted;
    exports io.jguard.samples.sandbox.worker;
    exports io.jguard.samples.sandbox.config;
}
