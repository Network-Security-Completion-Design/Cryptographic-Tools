import java.util.Random;

public class Good {
    public static int generateRandomInteger(int min, int max) {
        Random random = new Random();
        return random.nextInt(max - min + 1) + min;
    }

    public static void main(String[] args) {
        int randomNumber = generateRandomInteger(1, 100); // 生成范围在 1 到 100 之间的随机整数
        System.out.println("Random Number in Java: " + randomNumber);
    }
}
