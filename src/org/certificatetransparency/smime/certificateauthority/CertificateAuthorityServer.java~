package org.certificatetransparency.smime.certificateauthority;

import java.net.ServerSocket;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CertificateAuthorityServer implements Runnable {
	private int serverPort;
	private ServerSocket serverSocket;
	private ExecutorService threadPool = Executors.newFixedThreadPool(20);

	public CertificateAuthorityServer(int port) {
		this.serverPort = port;
	}

	public void run() {
		try {
			serverSocket = new ServerSocket(this.serverPort);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		while (true) {
			try {
				threadPool.execute(new ClientHandler(serverSocket.accept(), "Thread Pooled Server"));
			} catch (IOException e) {
				this.threadPool.shutdown();
				System.out.println("Server Stopped.");
			}
		}
	}

	public static void main(String arg[]) {
		CertificateAuthorityServer caServer = new CertificateAuthorityServer(Integer.parseInt("9999"));
		System.out.println("server is running on port 9999");
		ClientHandler.loadData("localhost", "/home/stdadmin/cacert/ca3.pem",
				"/home/stdadmin/cacert/pkcs8_key3", "ITSecurity", "uni-Bonn", "DE", "NRW", "Bonn");
		new Thread(caServer).start();
	}
}
