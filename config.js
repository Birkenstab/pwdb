module.exports = {
    port: 50173,
    useProxy: true, //Set whether a proxy is used. If this is false ssl will be activated and certificate and key must be specified
    trustProxy: "loopback", //Specifiy wich proxy do you want to trust (use "loopback on Unix system if you use it with a proxy on the same machine). This can be a hostname too
    sslKey: "/etc/apache2/ssl/apache.key", //Path where the ssl private key is located (leave it blank if you use a proxy)
    sslCert: "/etc/apache2/ssl/apache.crt", //Path where the ssl certificate is located (leave it blank if you use a proxy)
    hostBind: "localhost", //Host the http-server should be bound to (use "localhost" if you use it with a proxy on the same machine)

    //Things to leave alone
    skipAccountActivation: true,
    sessionexpires: 3600*24,
    passwordAttempts: [ //Muss von der kürzesten zum Längsten Zeitraum gehen
        {period: 1*1000, skip: 3, multiplicator: 0.5*1000}, //Zeitraum: 1 Sekunde; 3 Aufrufe werden abgezogen; mit _passwordAttemptExponent (1,5) potentiert; alles wird mit 0,5 multipliziert
        {period: 1*60*1000, skip: 20, multiplicator: 0.3*1000}, //usw.
        {period: 15*60*1000, skip: 30, multiplicator: 0.25*1000},
        {period: 2*60*60*1000, skip: 50, multiplicator: 0.1*1000},
        {period: 24*60*60*1000, skip: 100, multiplicator: 0.1*1000}
    ],
    passwordAttemptExponent: 1.5, //Verzögerung wird hiermit potentiert
    passwordAttemptIPMultiplicator: 3 //Bei IP-Verzögerung werden die Skips hiermit multipliziert
};
