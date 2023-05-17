package rlweipfe;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.helper.HelpScreenException;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.Namespace;

public class Main {

	private static final Map<String, Consumer<String[]>> COMMANDS = Map.ofEntries(
			Map.entry("genParams", Main::genParams),
			Map.entry("genSecretKey", Main::genSecretKey),
			Map.entry("genPublicKey", Main::genPublicKey),
			Map.entry("deriveFuncKey", Main::deriveFuncKey),
			Map.entry("encrypt", Main::encrypt),
			Map.entry("decrypt", Main::decrypt),
			Map.entry("decryptAll", Main::decryptAll),
			Map.entry("randomVector", Main::randomVector),
			Map.entry("randomMatrix", Main::randomMatrix),
			Map.entry("testDot", Main::testDot));

	public static void main(String[] args) {
		var cmdStream = IntStream.builder();
		cmdStream.accept(0);
		for(int i = 0; i < args.length; ++i) {
			if(COMMANDS.containsKey(args[i])) {
				cmdStream.accept(i);
			}
		}
		cmdStream.accept(args.length);
		int[] cmdi = cmdStream.build().toArray();
		if(cmdi.length == 2) {
			System.out.println("Valid commands: %s".formatted(COMMANDS.keySet()));
		}
		for(int i = 1; i < cmdi.length-1; ++i) {
			int cmdStart = cmdi[i];
			int cmdEnd = cmdi[i+1];
			String cmd = args[cmdStart];
			if(!COMMANDS.containsKey(cmd)) {
				throw new IllegalStateException();
			}
			String[] cmdArgs = Arrays.copyOfRange(args, cmdStart+1, cmdEnd);
			COMMANDS.get(cmd).accept(cmdArgs);
		}
	}

	private static SecureRandom rand = new SecureRandom();
	private static RLWEIPFE rlwe;
	private static RLWEIPFESecretKey msk;
	private static RLWEIPFEPublicKey mpk;
	private static RLWEIPFEFunctionKey skY;

	private static void genParams(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("genParams").build();
		parser.addArgument("-l").type(Integer.class).required(true).help("length of vectors");
		parser.addArgument("-n").type(Integer.class).setDefault(1).help("number of secret vectors");
		parser.addArgument("-x").type(Integer.class).required(true).help("bound of secret vectors");
		parser.addArgument("-y").type(Integer.class).required(true).help("bound of function vector");
		parser.addArgument("-k").type(Integer.class).setDefault(128).help("security parameter");
		parser.addArgument("-o").type(String.class).help("output file");
		try {
			Namespace ns = parser.parseArgs(args);
			int l = ns.getInt("l");
			int n = ns.getInt("n");
			int x = ns.getInt("x");
			int y = ns.getInt("y");
			int k = ns.getInt("k");
			String o = ns.getString("o");
			System.out.println("Generating parameters");
			long time = System.nanoTime();
			rlwe = RLWEIPFE.generate(k, l, n, x, y);
			time = System.nanoTime()-time;
			System.out.println("Parameter generation done in %f ms".formatted(time/1000000D));
			if(o != null) {
				System.out.println("Writing parameters to %s".formatted(o));
				writeObject(Path.of(o), rlwe.params);
			}
		}
		catch(HelpScreenException e) {
			// NO-OP
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void genSecretKey(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("genMSK").build();
		parser.addArgument("-p").type(String.class).help("params file");
		parser.addArgument("-o").type(String.class).help("output file");
		try {
			Namespace ns = parser.parseArgs(args);
			String p = ns.getString("p");
			String o = ns.getString("o");
			if(p != null) {
				System.out.println("Reading parameters from %s".formatted(p));
				rlwe = new RLWEIPFE(readObject(Path.of(p)));
			}
			if(rlwe == null) {
				System.err.println("Parameters missing");
				System.exit(1);
			}
			System.out.println("Generating secret key");
			long time = System.nanoTime();
			msk = rlwe.generateSecretKey(rand);
			time = System.nanoTime()-time;
			System.out.println("Secret key generation done in %f ms".formatted(time/1000000D));
			if(o != null) {
				System.out.println("Writing secret key to %s".formatted(o));
				writeObject(Path.of(o), msk);
			}
		}
		catch(HelpScreenException e) {
			// NO-OP
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void genPublicKey(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("genMPK").build();
		parser.addArgument("-p").type(String.class).help("params file");
		parser.addArgument("-k").type(String.class).help("secret key file");
		parser.addArgument("-o").type(String.class).help("output file");
		try {
			Namespace ns = parser.parseArgs(args);
			String p = ns.getString("p");
			String k = ns.getString("k");
			String o = ns.getString("o");
			if(p != null) {
				System.out.println("Reading parameters from %s".formatted(p));
				rlwe = new RLWEIPFE(readObject(Path.of(p)));
			}
			if(k != null) {
				System.out.println("Reading secret key from %s".formatted(k));
				msk = readObject(Path.of(k));
			}
			if(rlwe == null) {
				System.err.println("Parameters missing");
				System.exit(1);
			}
			if(msk == null) {
				System.err.println("Secret key missing");
				System.exit(1);
			}
			System.out.println("Generating public key");
			long time = System.nanoTime();
			mpk = rlwe.generatePublicKey(msk, rand);
			time = System.nanoTime()-time;
			System.out.println("Public key generation done in %f ms".formatted(time/1000000D));
			if(o != null) {
				System.out.println("Writing public key to %s".formatted(o));
				writeObject(Path.of(o), mpk);
			}
		}
		catch(HelpScreenException e) {
			// NO-OP
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void deriveFuncKey(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("deriveFuncKey").build();
		parser.addArgument("-p").type(String.class).help("params file");
		parser.addArgument("-y").type(String.class).required(true).help("function vector file");
		parser.addArgument("-k").type(String.class).help("secret key file");
		parser.addArgument("-o").type(String.class).help("output file");
		try {
			Namespace ns = parser.parseArgs(args);
			String p = ns.getString("p");
			String y = ns.getString("y");
			String k = ns.getString("k");
			String o = ns.getString("o");
			if(p != null) {
				System.out.println("Reading parameters from %s".formatted(p));
				rlwe = new RLWEIPFE(readObject(Path.of(p)));
			}
			System.out.println("Reading function vector from %s".formatted(y));
			int[] vy = readVector(Path.of(y));
			if(k != null) {
				System.out.println("Reading secret key from %s".formatted(k));
				msk = readObject(Path.of(k));
			}
			if(rlwe == null) {
				System.err.println("Parameters missing");
				System.exit(1);
			}
			if(msk == null) {
				System.err.println("Secret key missing");
				System.exit(1);
			}
			System.out.println("Deriving function key");
			long time = System.nanoTime();
			skY = rlwe.deriveFunctionKey(vy, msk);
			time = System.nanoTime()-time;
			System.out.println("Function key derivation done in %f ms".formatted(time/1000000D));
			if(o != null) {
				System.out.println("Writing function key to %s".formatted(o));
				writeObject(Path.of(o), skY);
			}
		}
		catch(HelpScreenException e) {
			// NO-OP
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void encrypt(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("encrypt").build();
		parser.addArgument("-p").type(String.class).help("params file");
		parser.addArgument("-x").type(String.class).required(true).help("secret matrix file");
		parser.addArgument("-k").type(String.class).help("public key file");
		parser.addArgument("-s").type(Boolean.class).action(Arguments.storeTrue()).help("encrypt single");
		parser.addArgument("-o").type(String.class).required(true).help("output file");
		try {
			Namespace ns = parser.parseArgs(args);
			String p = ns.getString("p");
			String x = ns.getString("x");
			String k = ns.getString("k");
			boolean s = ns.getBoolean("s");
			String o = ns.getString("o");
			if(p != null) {
				System.out.println("Reading parameters from %s".formatted(p));
				rlwe = new RLWEIPFE(readObject(Path.of(p)));
			}
			System.out.println("Reading secret matrix from %s".formatted(x));
			int[][] mx = readMatrix(Path.of(x));
			if(k != null) {
				System.out.println("Reading public key from %s".formatted(k));
				mpk = readObject(Path.of(k));
			}
			if(rlwe == null) {
				System.err.println("Parameters missing");
				System.exit(1);
			}
			if(mpk == null) {
				System.err.println("Public key missing");
				System.exit(1);
			}
			System.out.println("Encrypting");
			long time = System.nanoTime();
			RLWEIPFECiphertext ct = s ? rlwe.encryptSingle(mx[0], mpk, rand) : rlwe.encryptMulti(mx, mpk, rand);
			time = System.nanoTime()-time;
			System.out.println("Encryption done in %f ms".formatted(time/1000000D));
			System.out.println("Writing ciphertext to %s".formatted(o));
			writeObject(Path.of(o), ct);
		}
		catch(HelpScreenException e) {
			// NO-OP
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void decrypt(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("decrypt").build();
		parser.addArgument("-p").type(String.class).help("params file");
		parser.addArgument("-c").type(String.class).required(true).help("ciphertext file");
		parser.addArgument("-k").type(String.class).help("function key file");
		parser.addArgument("-o").type(String.class).help("output file");
		try {
			Namespace ns = parser.parseArgs(args);
			String p = ns.getString("p");
			String c = ns.getString("c");
			String k = ns.getString("k");
			String o = ns.getString("o");
			if(p != null) {
				System.out.println("Reading parameters from %s".formatted(p));
				rlwe = new RLWEIPFE(readObject(Path.of(p)));
			}
			System.out.println("Reading ciphertext from %s".formatted(c));
			RLWEIPFECiphertext ct = readObject(Path.of(c));
			if(k != null) {
				System.out.println("Reading function key from %s".formatted(k));
				skY = readObject(Path.of(k));
			}
			if(rlwe == null) {
				System.err.println("Parameters missing");
				System.exit(1);
			}
			if(skY == null) {
				System.err.println("Function key missing");
				System.exit(1);
			}
			System.out.println("Decrypting");
			long time = System.nanoTime();
			BigInteger[] xy = rlwe.decrypt(ct, skY);
			time = System.nanoTime()-time;
			System.out.println("Decryption done in %f ms".formatted(time/1000000D));
			System.out.println("Result:");
			System.out.println(Arrays.toString(xy));
			if(o != null) {
				System.out.println("Writing result to %s".formatted(o));
				writeVector(Path.of(o), xy);
			}
		}
		catch(HelpScreenException e) {
			// NO-OP
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void decryptAll(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("decrypt").build();
		parser.addArgument("-p").type(String.class).help("params file");
		parser.addArgument("-c").type(String.class).required(true).help("ciphertext file");
		parser.addArgument("-k").type(String.class).help("secret key file");
		parser.addArgument("-o").type(String.class).required(true).help("output file");
		try {
			Namespace ns = parser.parseArgs(args);
			String p = ns.getString("p");
			String c = ns.getString("c");
			String k = ns.getString("k");
			String o = ns.getString("o");
			if(p != null) {
				System.out.println("Reading parameters from %s".formatted(p));
				rlwe = new RLWEIPFE(readObject(Path.of(p)));
			}
			System.out.println("Reading ciphertext from %s".formatted(c));
			RLWEIPFECiphertext ct = readObject(Path.of(c));
			if(k != null) {
				System.out.println("Reading function key from %s".formatted(k));
				msk = readObject(Path.of(k));
			}
			if(rlwe == null) {
				System.err.println("Parameters missing");
				System.exit(1);
			}
			if(msk == null) {
				System.err.println("Secret key missing");
				System.exit(1);
			}
			System.out.println("Decrypting");
			long time = System.nanoTime();
			int[][] x = rlwe.decryptAll(ct, msk);
			time = System.nanoTime()-time;
			System.out.println("Decryption done in %f ms".formatted(time/1000000D));
			System.out.println("Writing result to %s".formatted(o));
			writeMatrix(Path.of(o), x);
		}
		catch(HelpScreenException e) {
			// NO-OP
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void randomVector(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("randomVector").build();
		parser.addArgument("-l").type(Integer.class).required(true).help("vector length");
		parser.addArgument("-b").type(Integer.class).required(true).help("vector bounds");
		parser.addArgument("-o").type(String.class).required(true).help("output file");
		try {
			Namespace ns = parser.parseArgs(args);
			int l = ns.getInt("l");
			int b = Math.abs(ns.getInt("b"));
			String o = ns.getString("o");
			System.out.println("Generating random vector");
			int[] ints = rand.ints(-b, b+1).limit(l).toArray();
			System.out.println("Writing random vector to %s".formatted(o));
			writeVector(Path.of(o), ints);
		}
		catch(HelpScreenException e) {
			// NO-OP
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void randomMatrix(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("randomMatrix").build();
		parser.addArgument("-c").type(Integer.class).required(true).help("matrix columns");
		parser.addArgument("-r").type(Integer.class).required(true).help("matrix rows");
		parser.addArgument("-b").type(Integer.class).required(true).help("matrix bounds");
		parser.addArgument("-o").type(String.class).required(true).help("output file");
		try {
			Namespace ns = parser.parseArgs(args);
			int c = ns.getInt("c");
			int r = ns.getInt("r");
			int b = Math.abs(ns.getInt("b"));
			String o = ns.getString("o");
			System.out.println("Generating random matrix");
			int[][] ints = Stream.generate(()->rand.ints(-b, b+1).limit(c).toArray()).limit(r).toArray(int[][]::new);
			System.out.println("Writing random matrix to %s".formatted(o));
			writeMatrix(Path.of(o), ints);
		}
		catch(HelpScreenException e) {
			// NO-OP
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void testDot(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("testDot").build();
		parser.addArgument("-x").type(String.class).required(true).help("matrix file");
		parser.addArgument("-y").type(String.class).required(true).help("vector file");
		try {
			Namespace ns = parser.parseArgs(args);
			String x = ns.getString("x");
			String y = ns.getString("y");
			System.out.println("Reading matrix from %s".formatted(x));
			int[][] mat = readMatrix(Path.of(x));
			System.out.println("Reading vector from %s".formatted(y));
			int[] vec = readVector(Path.of(y));
			System.out.println("Result:");
			System.out.println(Arrays.stream(mat).map(row->Arith.dot(row, vec)).toList());
		}
		catch(HelpScreenException e) {
			// NO-OP
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static <T> void writeObject(Path path, T obj) throws IOException {
		try(var oos = new ObjectOutputStream(Files.newOutputStream(path))) {
			oos.writeObject(obj);
		}
	}

	private static <T> T readObject(Path path) throws IOException, ClassNotFoundException {
		try(var ois = new ObjectInputStream(Files.newInputStream(path))) {
			return (T)ois.readObject();
		}
	}

	private static void writeVector(Path path, int[] vector) throws IOException {
		try(var writer = Files.newBufferedWriter(path)) {
			String line = Arrays.stream(vector).mapToObj(String::valueOf).collect(Collectors.joining(" "));
			writer.append(line);
		}
	}

	private static void writeVector(Path path, Number[] vector) throws IOException {
		try(var writer = Files.newBufferedWriter(path)) {
			String line = Arrays.stream(vector).map(String::valueOf).collect(Collectors.joining(" "));
			writer.append(line);
		}
	}

	private static int[] readVector(Path path) throws IOException {
		try(var stream = Files.lines(path)) {
			return stream.flatMapToInt(s->Arrays.stream(s.split("[,\\s]+")).
					filter(s1->!s1.isBlank()).
					mapToInt(Integer::valueOf)).
					toArray();
		}
	}

	private static void writeMatrix(Path path, int[][] matrix) throws IOException {
		try(var writer = Files.newBufferedWriter(path)) {
			for(int[] row : matrix) {
				String line = Arrays.stream(row).mapToObj(String::valueOf).collect(Collectors.joining(" "));
				writer.append(line);
				writer.newLine();
			}
		}
	}

	private static int[][] readMatrix(Path path) throws IOException {
		try(var stream = Files.lines(path)) {
			return stream.filter(s->!s.isBlank()).
					map(s->Arrays.stream(s.split("[,\\s]+")).
							filter(s1->!s1.isBlank()).
							mapToInt(Integer::valueOf).
							toArray()).
					toArray(int[][]::new);
		}
	}
}
