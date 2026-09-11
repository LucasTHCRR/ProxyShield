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

package de.lucasthcr.bridgesave.proxyshield.notify;

import de.lucasthcr.bridgesave.proxyshield.config.ConfigNode;
import java.util.ArrayList;
import java.util.List;

/**
 * The shape of the Discord embed, as the operator wrote it.
 * <p>
 * The layout used to be fixed at a title and six inline boxes. Servers word their staff channels
 * differently, and the one thing an operator cannot do from outside is change what the message
 * looks like, so every visible part is a template string here instead.
 * <p>
 * Values are substituted exactly as written. That is deliberate: Discord parses embed text as
 * Markdown, so whether a player name belongs in a code span is a formatting decision, and the
 * person writing the layout is the one who should make it. The shipped default wraps the values
 * that can contain an underscore, because a Minecraft name legitimately can.
 */
public final class EmbedTemplate {

   /** Cap on configured fields, matching what Discord accepts in one embed. */
   private static final int MAX_FIELDS = 25;

   private final String title;
   private final String description;
   private final String thumbnail;
   private final String footer;
   private final List<Field> fields;

   private EmbedTemplate(String title, String description, String thumbnail, String footer,
         List<Field> fields) {
      this.title = title;
      this.description = description;
      this.thumbnail = thumbnail;
      this.footer = footer;
      this.fields = List.copyOf(fields);
   }

   /**
    * The layout every release before 2.4 sent, used when {@code discord.embed} is absent.
    * <p>
    * An existing config predates the section entirely, and an update must not change how a
    * server's alerts look, so the old shape stays the fallback rather than the new default.
    *
    * @param title what {@code discord.title} was set to
    */
   public static EmbedTemplate classic(String title) {
      return new EmbedTemplate(title, "", "", "ProxyShield {version} on {platform}", List.of(
            new Field("Player", "`{player}`", true),
            new Field("IP", "`{ip}`", true),
            new Field("Country", "{country}", true),
            new Field("Reason", "{reason}", true),
            new Field("ISP", "`{isp}`", true),
            new Field("Action", "{action}", true)));
   }

   /**
    * Reads {@code discord.embed}, falling back to {@link #classic(String)} when it is not there.
    *
    * @param fallbackTitle {@code discord.title}, used when the section sets no title of its own
    */
   public static EmbedTemplate from(ConfigNode node, String fallbackTitle) {
      if (node.getKeys("discord.embed").isEmpty()) {
         return classic(fallbackTitle);
      }

      String title = node.getString("discord.embed.title", "");
      return new EmbedTemplate(
            title.isEmpty() ? fallbackTitle : title,
            node.getString("discord.embed.description", ""),
            node.getString("discord.embed.thumbnail", ""),
            node.getString("discord.embed.footer", "ProxyShield {version} on {platform}"),
            readFields(node));
   }

   /**
    * Reads the fields as a section keyed by their heading.
    * <p>
    * A YAML list of maps cannot be addressed through {@link ConfigNode}'s dotted paths, and naming
    * the entries is how {@code api.providers} already works, so the two sections read the same way.
    * File order is kept, which is the order they appear in the message.
    */
   private static List<Field> readFields(ConfigNode node) {
      List<Field> out = new ArrayList<>();
      for (String name : node.getKeys("discord.embed.fields")) {
         if (out.size() >= MAX_FIELDS) {
            break;
         }
         String path = "discord.embed.fields." + name;
         String value = node.getString(path + ".value", "");
         if (!value.isEmpty()) {
            out.add(new Field(name, value, node.getBoolean(path + ".inline", true)));
         }
      }
      return out;
   }

   public String title() {
      return title;
   }

   public String description() {
      return description;
   }

   public String thumbnail() {
      return thumbnail;
   }

   public String footer() {
      return footer;
   }

   public List<Field> fields() {
      return fields;
   }

   /** One box in the embed. {@code inline} is what puts three of them on a row. */
   public record Field(String name, String value, boolean inline) {
   }
}
