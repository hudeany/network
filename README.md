# network
Java Network Utilities (HTTP / WakeOnLan / TLS-Cert-Check))

## Basic HTTP Request:
```
import java.io.File;
import java.net.InetSocketAddress;
import java.net.Proxy;

import javax.net.ssl.TrustManager;

import de.soderer.network.HttpRequest;
import de.soderer.network.HttpRequest.HttpMethod;
import de.soderer.network.HttpResponse;
import de.soderer.network.HttpUtilities;
import de.soderer.network.TrustManagerUtilities;

public class SimpleTest {
	public static void main(final String[] args) throws Exception {
		try {
			final HttpRequest request = new HttpRequest(HttpMethod.GET, "https://mySite.com");

			final String proxyUrl = "proxy.url";
			final int proxyPort = 8080;
			Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyUrl, proxyPort));
			
			// Use this for no proxy
			//proxy = java.net.Proxy.NO_PROXY;

			// Default systems trusted certificate check: null
			TrustManager trustManager = null;

			// Use this to use your own defined p12 trusted KeyStore file
			//trustManager = TrustManagerUtilities.createTrustManagerForKeyStore(new File("myKeyStore.p12"));

			// Use this to deactivate any TLS server certificate check
			//trustManager = TrustManagerUtilities.createTrustAllTrustManager();

			final HttpResponse response = HttpUtilities.executeHttpRequest(request, proxy, trustManager);

			if (response.getHttpCode() == 200) {
				System.out.println(response);
			} else {
				System.out.println("Error: " + response.getHttpCode());
			}
		} catch (final Exception e) {
			System.out.println("Error: " + e.getMessage());
		}
	}
}
```

## Wake On LAN (WOL):
```
String macAddressString = "00:80:41:AE:FD:7E";
NetworkUtilities.wakeOnLanPing(macAddressString)
```
