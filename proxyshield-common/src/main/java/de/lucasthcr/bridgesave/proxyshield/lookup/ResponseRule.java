/*
 * ProxyShield - Proxy and VPN protection plugin
 * Copyright (C) 2026  LucasTHCR
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package de.lucasthcr.bridgesave.proxyshield.lookup;

import de.lucasthcr.bridgesave.proxyshield.util.Json;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A group of comparisons against fields of a provider answer, all of which must hold.
 * <p>
 * Lets an operator say things a plain field mapping cannot: "a fraud score of 75 or more is a
 * VPN", or "whatever the flags say, a mobile connection is fine". Several groups on the same
 * provider are alternatives, so the provider-level semantics are OR over groups, AND inside one.
 * <p>
 * Each condition is written as {@code <path> <op> <value>}, for example {@code risk.score >= 75}
 * or {@code connection.type = mobile}. Numbers compare numerically, anything else compares as
 * case-insensitive text. A field that is missing from the answer never satisfies a condition, so
 * a rule cannot fire on a response that simply did not carry the data.
 */
public final class ResponseRule {

   private static final Pattern SYNTAX =
         Pattern.compile("^\\s*(\\S+?)\\s*(>=|<=|!=|==|=|>|<)\\s*(.*?)\\s*$");

   private enum Op {
      EQ, NE, GT, GE, LT, LE
   }

   private record Condition(String path, Op op, String value) {
   }

   private final String name;
   private final List<Condition> conditions;

   private ResponseRule(String name, List<Condition> conditions) {
      this.name = name;
      this.conditions = conditions;
   }

   /**
    * Parses one group.
    *
    * @throws IllegalArgumentException naming the condition that could not be read
    */
   public static ResponseRule parse(String name, List<String> lines) {
      List<Condition> parsed = new ArrayList<>(lines.size());
      for (String line : lines) {
         if (line == null || line.isBlank()) {
            continue;
         }
         Matcher matcher = SYNTAX.matcher(line);
         if (!matcher.matches() || matcher.group(3).isEmpty()) {
            throw new IllegalArgumentException("cannot read condition '" + line
                  + "', expected '<field> <op> <value>' with op one of = != > >= < <=");
         }
         parsed.add(new Condition(matcher.group(1), op(matcher.group(2)),
               unquote(matcher.group(3))));
      }
      if (parsed.isEmpty()) {
         throw new IllegalArgumentException("rule '" + name + "' has no conditions");
      }
      return new ResponseRule(name, List.copyOf(parsed));
   }

   private static Op op(String symbol) {
      return switch (symbol) {
         case "!=" -> Op.NE;
         case ">" -> Op.GT;
         case ">=" -> Op.GE;
         case "<" -> Op.LT;
         case "<=" -> Op.LE;
         default -> Op.EQ;
      };
   }

   private static String unquote(String value) {
      if (value.length() >= 2 && (value.startsWith("\"") && value.endsWith("\"")
            || value.startsWith("'") && value.endsWith("'"))) {
         return value.substring(1, value.length() - 1);
      }
      return value;
   }

   public String name() {
      return name;
   }

   /** Whether every condition holds for the given parsed answer. */
   public boolean matches(Object node) {
      for (Condition condition : conditions) {
         if (!holds(node, condition)) {
            return false;
         }
      }
      return true;
   }

   private static boolean holds(Object node, Condition condition) {
      Object actual = Json.path(node, condition.path());
      if (actual == null) {
         return false;
      }
      Double left = asNumber(actual);
      Double right = asNumber(condition.value());
      if (left != null && right != null) {
         int compared = Double.compare(left, right);
         return switch (condition.op()) {
            case EQ -> compared == 0;
            case NE -> compared != 0;
            case GT -> compared > 0;
            case GE -> compared >= 0;
            case LT -> compared < 0;
            case LE -> compared <= 0;
         };
      }
      String text = String.valueOf(actual).trim().toLowerCase(Locale.ROOT);
      String expected = condition.value().toLowerCase(Locale.ROOT);
      return switch (condition.op()) {
         case EQ -> text.equals(expected);
         case NE -> !text.equals(expected);
         // Ordering only makes sense for numbers; a text field never satisfies one.
         default -> false;
      };
   }

   private static Double asNumber(Object value) {
      if (value instanceof Number number) {
         return number.doubleValue();
      }
      if (value instanceof String text) {
         try {
            return Double.parseDouble(text.trim());
         } catch (NumberFormatException notANumber) {
            return null;
         }
      }
      return null;
   }

   /** Whether any of the groups matches. */
   public static ResponseRule firstMatch(List<ResponseRule> rules, Object node) {
      for (ResponseRule rule : rules) {
         if (rule.matches(node)) {
            return rule;
         }
      }
      return null;
   }
}
