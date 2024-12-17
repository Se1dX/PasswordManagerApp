package org.example.PasswordManagerApp;
import java.util.*;
import java.security.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class PasswordManagerApp {

	// шифрование Base64
	static class Base64Encryptor {
		public static String encrypt(String input) {
			try {
				return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
			} catch (Exception e) {
				System.err.println("Ошибка при шифровании Base64: " + e.getMessage());
				return null;
			}
		}

		public static String decrypt(String encrypted) {
			try {
				byte[] decodedBytes = Base64.getDecoder().decode(encrypted);
				return new String(decodedBytes, StandardCharsets.UTF_8);
			} catch (Exception e) {
				System.err.println("Ошибка при дешифровании Base64: " + e.getMessage());
				return null;
			}
		}
	}

	// шифрование MD5
	static class MD5Encryptor {
		public static String encrypt(String input) {
			try {
				MessageDigest md = MessageDigest.getInstance("MD5");
				byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
				StringBuilder hexString = new StringBuilder();
				for (byte b : hash) {
					hexString.append(String.format("%02x", b));
				}
				return hexString.toString();
			} catch (NoSuchAlgorithmException e) {
				System.err.println("Ошибка при хешировании MD5: " + e.getMessage());
				return null;
			}
		}
	}

	// шифрование по алгоритму Фейстеля (инвертирование строки)
	static class FeistelEncryptor {
		public static String encrypt(String input) {
			try {
				return new StringBuilder(input).reverse().toString();
			} catch (Exception e) {
				System.err.println("Ошибка при шифровании Feistel: " + e.getMessage());
				return null;
			}
		}
	}

	// шифрование с солью
	static class SaltedPasswordEncryptor {
		private static final String SALT = "randomSalt"; // соль для пароля

		public static String encrypt(String input) {
			try {
				String saltedPassword = input + SALT;
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] hash = md.digest(saltedPassword.getBytes(StandardCharsets.UTF_8));
				StringBuilder hexString = new StringBuilder();
				for (byte b : hash) {
					hexString.append(String.format("%02x", b));
				}
				return hexString.toString();
			} catch (NoSuchAlgorithmException e) {
				System.err.println("Ошибка при шифровании с солью: " + e.getMessage());
				return null;
			}
		}
	}

	// класс управления пользователями
	static class UserManager {
		private Map<String, String> users = new HashMap<>(); // логины и пароли
		private Map<String, String> encryptionMethods = new HashMap<>(); // методы шифрования

		// регистрация пользователя
		public boolean registerUser(String username, String password, String encryptionMethod) {
			if (username.trim().isEmpty() || password.trim().isEmpty()) {
				System.out.println("Имя пользователя и пароль не могут быть пустыми.");
				return false;
			}
			String encryptedPassword = encryptPassword(password, encryptionMethod);
			if (encryptedPassword != null) {
				users.put(username, encryptedPassword);
				encryptionMethods.put(username, encryptionMethod);  // сохраняем метод шифрования
				return true;
			}
			return false;
		}

		// проверка пароля при входе
		public boolean validateUser(String username, String password) {
			String storedPassword = users.get(username);
			String encryptionMethod = encryptionMethods.get(username);  // получаем метод шифрования
			if (storedPassword == null || encryptionMethod == null) {
				System.out.println("Пользователь не найден.");
				return false;
			}
			String encryptedPassword = encryptPassword(password, encryptionMethod);
			return storedPassword.equals(encryptedPassword);
		}

		// шифрование пароля
		private String encryptPassword(String password, String encryptionMethod) {
			switch (encryptionMethod) {
				case "1": // Base64
					return Base64Encryptor.encrypt(password);
				case "2": // MD5
					return MD5Encryptor.encrypt(password);
				case "3": // Feistel
					return FeistelEncryptor.encrypt(password);
				case "4": // Подсаливание
					return SaltedPasswordEncryptor.encrypt(password);
				default:
					return null;
			}
		}
	}

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8); // поддержка UTF-8
		UserManager userManager = new UserManager();

		while (true) {
			System.out.println("\nМеню:");
			System.out.println("1. Регистрация");
			System.out.println("2. Вход");
			System.out.println("3. Выход");
			System.out.print("Выберите опцию: ");
			String choice = scanner.nextLine();

			if (choice.equals("3")) {
				System.out.println("Выход из приложения.");
				break;
			}

			switch (choice) {
				case "1": // регистрация
					System.out.print("Введите логин: ");
					String username = scanner.nextLine();

					System.out.print("Введите пароль: ");
					String password = scanner.nextLine();

					if (username.trim().isEmpty() || password.trim().isEmpty()) {
						System.out.println("Имя пользователя и пароль не могут быть пустыми.");
						break;
					}

					System.out.println("Выберите метод шифрования:");
					System.out.println("1. Base64");
					System.out.println("2. MD5");
					System.out.println("3. Feistel");
					System.out.println("4. Подсаливание");
					System.out.print("Ваш выбор: ");
					String encryptionMethod = scanner.nextLine();

					if (userManager.registerUser(username, password, encryptionMethod)) {
						System.out.println("Пользователь успешно зарегистрирован!");
					} else {
						System.out.println("Ошибка при регистрации пользователя.");
					}
					break;

				case "2": // вход
					System.out.print("Введите логин для входа: ");
					String login = scanner.nextLine();

					System.out.print("Введите пароль: ");
					String enteredPassword = scanner.nextLine();

					if (userManager.validateUser(login, enteredPassword)) {
						System.out.println("Вход успешен!");
					} else {
						System.out.println("Неверный пароль.");
					}
					break;

				default:
					System.out.println("Некорректный выбор. Попробуйте снова.");
			}
		}

		scanner.close();
	}
}
