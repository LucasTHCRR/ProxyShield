package de.lucasthcr.bridgesave.proxyshield.util;

import java.util.Map;

/**
 * Message helpers.
 * <p>
 * The core always hands platform code text that still carries {@code &} colour codes; translating
 * those into whatever the platform expects is the adapter's job.
 */
public final class Text {

   private Text() {
   }

   /** Replaces every {@code {key}} placeholder. Unknown placeholders are left untouched. */
   public static String fill(String template, Map<String, String> placeholders) {
      if (template == null || template.isEmpty()) {
         return "";
      }

      String result = template;
      for (Map.Entry<String, String> entry : placeholders.entrySet()) {
         String value = entry.getValue() == null ? "" : entry.getValue();
         result = result.replace("{" + entry.getKey() + "}", value);
      }
      return result.replace("\\n", "\n");
   }

   /** Removes {@code &} and {@code §} colour codes, for log files and webhook payloads. */
   public static String stripColors(String input) {
      if (input == null || input.isEmpty()) {
         return "";
      }

      StringBuilder out = new StringBuilder(input.length());
      for (int i = 0; i < input.length(); i++) {
         char c = input.charAt(i);
         if ((c == '&' || c == '§') && i + 1 < input.length()
               && isColorCode(input.charAt(i + 1))) {
            i++;
            continue;
         }
         out.append(c);
      }
      return out.toString();
   }

   private static boolean isColorCode(char c) {
      return "0123456789AaBbCcDdEeFfKkLlMmNnOoRrXx".indexOf(c) >= 0;
   }

   /** Truncates to {@code max} characters, appending an ellipsis when it had to cut. */
   public static String clip(String input, int max) {
      if (input == null) {
         return "";
      }
      return input.length() <= max ? input : input.substring(0, Math.max(0, max - 3)) + "...";
   }
}
