 
package securityhw;

import java.util.Arrays;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
 


/**
 *
 * @author liron
 */
public class VigenereCipher {

    /**
     * Relative frequencies of letters from A to Z in the English
     * alphabet. (probability distribution: the sum is approximately 1)
     */
    private final static double frequencies[] = { 0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, 0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.001, 0.020, 0.001}; 

    /**
     * Encrypts plain text with a key with Vigenere Algorithm
     * @param text Plain  text will be encrypt
     * @param key will be use for encrypt the text
     * @return  Encrypted Text
     */
    public static String encrypt(String text, final String key)
   {
       String res = "";
       text = text.toUpperCase();
       
       for (int i = 0, j = 0; i < text.length(); i++)
       {
           char c = text.charAt(i);
           if (c < 'A' || c > 'Z')
               continue;
           res += (char) ((c + key.charAt(j) - 2 * 'A') % 26 + 'A');
           j = ++j % key.length();
       }
       return res;
   }
    
    /**
     * Decrypts Vigenere encrypted text
     * @param text Encrypted Text  for decrypt
     * @param key will be use for decrypting the text
     * @return plain text 
     */
      public static String decrypt(String text, final String key)
   {
       String res = "";
       text = text.toUpperCase();
       for (int i = 0, j = 0; i < text.length(); i++)
       {
           char c = text.charAt(i);
           if (c < 'A' || c > 'Z')
               continue;
           res += (char) ((c - key.charAt(j) + 26) % 26 + 'A');
           j = ++j % key.length();
       }
       return res;
   }
    
/**
 * Computes the Occurrences of each of the English letters within a given input string. 
 * The returned array is of size 26
 * @param ciphertext
 * @return 
 */
    public static double[] getOccurrences(String ciphertext){
 
        double[] occurences = new double[26];
        Arrays.fill(occurences,0.0);
        int n = ciphertext.length();

        for(int i = 0 ; i < n ; i++)
        {
            int letterPosition = ciphertext.charAt(i) - 'A';
            occurences[letterPosition]++;
        }
        /*
        for(int i = 0 ; i < 26 ; i++)
            occurences[i] = occurences[i]/n;
        */
        return occurences;
    }
      
     /**
      * Get index of coincidence.
      * index of coincidence = sigma (f_i * ( f_i - 1)) / (n*(n-1))
      * f_i means Occurrences. n means the length of the cipher text.
      * @param ciphertext
      * @return 
      */
    public static  double getIndexOfCoincidence(String ciphertext){
 
        double ic=0.0;
        double[] fq = getOccurrences(ciphertext);
 
        for(int i=0; i<26; i++)
                ic += fq[i]*(fq[i]-1);
 
        int n = ciphertext.length();
 
        ic = (ic) / (n*(n-1));
        //System.out.println("ic : " + ic);
        return ic; 
    }

 
   /**
    * Finds best key length, 
    * Tries every key length from 1 to length of the cipher text.
    * if the average of index of coincidence is between in 0.060~0.080,
    * return the key length.
    * @param ciphertext
    * @return 
    */
    public static int findKeyLength(String ciphertext){

        int k = 1; 
        int n = ciphertext.length();
        String y;
        double icAverage;
 
        for( k = 1; k < n; k++){
                icAverage = 0;
                for(int l=0;l<k;l++){
                        y = getSubString(ciphertext, l, k);
                        icAverage += getIndexOfCoincidence(y);
                }
 
                icAverage /= k;
 
                //System.out.println("k, icAverage : " + k + ", " + icAverage);
                if(0.060 < icAverage && icAverage <= 0.080)
                {break;}
        }
        //System.out.println("key length : " + k);
        return k;
    } 
    
    
    /**
     * Finds the best key for a given ciphertext and a given key length.
     * Defines keyLength substrings by breaking the ciphertext in columns,
     * for each substring finds the best key for Ceasar, i.e. shift, decryption,
     * and builds the required key. 
     * @param ciphertext
     * @param keyLength
     * @return 
     */
    public static String findKey(String ciphertext, int keyLength)
     {
        String bestKey = "";
        String y;
        int keyY;
 
        
 
        for(int i = 0; i < keyLength; i++)
        {
            y = getSubString(ciphertext, i, keyLength);
            keyY = findBestKeyForDecryption(y);
            bestKey = bestKey + (char)(keyY +'A');
        }
        return bestKey;
     }
     
     
     /**
      * Finds best key for using Ceasar Decryption method,
      * Tries every key from 0 to 25, and calculates the deviation between
      * the frequency of English letters and the decrypted letters
      * returns the best key which gives minimal deviation value.
      * @param text
      * @return 
      */
     public static int findBestKeyForDecryption(String text){
 
        int key=0;
        double len=text.length();
        double min=1;
        double freq;
        String CeasarDecryptionText;
 
        for(int k=0; k<26; k++){
 
                freq = 0;
                // attempts to decrypt the cyphertext using ceasarshift. 
                CeasarDecryptionText = ceasarShift(text, k);
                double[] f = getOccurrences(CeasarDecryptionText);
                for(int j=0; j<26; j++){
                        // deviation method : deviation[i]= deviation[i]+(frequency[i] - English_frequency[i])^2
                        freq = freq + (f[j]/len - frequencies[j])*(f[j]/len - frequencies[j]); 
                }
 
                if(freq < min){
                        min = freq;
                        key = k;
                }
        }
                return key;
    }
     
     /**
      * Shift all letters of a input string by a given factor. 
      * Operations are modulo 26
      * @param ciphertext
      * @param shift
      * @return 
      */
     public static String ceasarShift(String ciphertext, int shift){
 
        int n = ciphertext.length();
        String res="";

        for(int i=0; i < n; i++){

            int cipherValue  =  ciphertext.charAt(i) -'A';
            int plainValue = ((cipherValue - shift + 26) % 26);//tricking the modulo with the +26
            res += (char)(plainValue + 'A');
        }
        return res;
    }
    

    /**
     * 
     * @param cryptotext
     * @param offset
     * @param stride
     * Selects a substring from a given input, by taking all letters
     * that are stride away, starting at offset
     * 
     * @return substring
     */
    public static String getSubString(String cryptotext, int offset, int stride){
 
        int n = cryptotext.length();
        int d = (n - 1) / stride ; // rounding on purpose
        String res="";
        for(int i=0;i<d;i++){
            res += cryptotext.charAt(offset + i*stride);
        }
        // don't forget the last ones
        if( d*stride + offset < n){ 
            res += cryptotext.charAt(offset + d*stride);
        }
        return res;
    }
  
    
  
    /**
     * Reads content of input file and returns it in a string in uppercase.
     * @param inputFile
     * @return 
     */
    public static String getTextFrom(String inputFile){
 
        String text = "";
 
        try{
            BufferedReader bufReader = new BufferedReader (new FileReader (inputFile));
            int lnum=0;

            do {
                String line = bufReader.readLine ();
                if (line == null) break;
                text += line;
                lnum++;
            } while (true);
 
            bufReader.close ();
            text = text.toUpperCase();
            
            System.out.println(lnum+" lines of text");
            return text;
            
        }catch(IOException ioe){
            
            System.out.println("IO Error: "+ioe.getMessage());
            System.out.println("Exiting...");
            System.exit(-1);
        }
        return text; // will not get there
    } 

 
    /**
     * Writes a text string into a file. 
     * Doesn't take care of already existence of the written file
     * @param text
     * @param outputFile 
     */
    public static void writeTextToFile(String text,String outputFile){
 
        try{
 
            Writer output = new BufferedWriter(new FileWriter(outputFile));
            output.write(text);
            output.close();
            
            System.out.println("Your file has been written"); 
 
        }catch(IOException ioe){
 
            System.out.println("Error: "+ioe.getMessage());
            System.exit(-1);
        }
    }
    
     
    /**
     * Prompts for the key as long as the input is not a non empty
     * word (just letters and at least one)
     * @return 
     */
    public static String getKeyFromPrompt(){
 
        String key="";
 
        try{
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            do{
                System.out.print("New key > ");
                key = br.readLine();
                if(key.length()==0){
                    System.out.println("Your key is empty, try again");
                }else if(!key.matches("[a-zA-Z]+")){
                    System.out.println("Your key is not a valid word, try again");
                }else {
 
                    System.out.println("here");
                    break;
 
                }
 
            }while(true);
            return key.toUpperCase();
 
        }catch(IOException ioe){
 
            System.out.println("IO Error: "+ioe.getMessage());
            System.out.println("Exiting...");
            System.exit(-1);

        }
        return key; // will not get there
    }  

    
    
    public static void usage(){
 
        String st="############"+"\n";
        st+=      "#  Usage:\n";
        st+=      "#\t Encryption: java Vigenere -e <plaintext> <ciphertext>"+"\n";
        st+=      "#\t Decryption: java Vigenere -d <ciphertext> <plaintext>"+"\n";
        st+=      "#\n############";
        System.out.println(st);
    }
 
 
    /**
     * @param args the command line arguments
     */  
    public static void main(String[] args) 
    {

        if(args.length < 3)
        {
            usage();
            return;
        }
        
        switch (args[0]) {
            case "de":
                {
                    String message = getTextFrom(args[1]);
                    String key = findKey(message,findKeyLength(message));
                    writeTextToFile(decrypt(message, key),args[2]);
                    break;
                }
            case "en":
                {
                    String message = getTextFrom(args[1]);
                    String key = getKeyFromPrompt();
                    writeTextToFile(decrypt(message, key),args[2]);
                    break;
                }
            default:
                usage();
                break;
        }
    }
    
}