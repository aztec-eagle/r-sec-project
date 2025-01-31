# r-sec-project

## Introduction

Cybersecurity is a critical area of focus. The area has grown rapidly
due to the increasing number of cyber-threats from various sources.
Sources includes individuals, criminal organizations, state actors, and
many more.

This project aims to analyze cybersecurity data from multiple datasets
and provide valuable insights into attack types, patterns, and vectors.
The main goal of this project is to identify relevant and interesting
trends that will contribute to the development of improved defensive
strategies.

## The Data: Cyber Attacks and Data Analysis

This project utilizes four distinct datasets and each will uniquely
contribute on building a clear perspective on cybersecurity incidents
and patterns:

<b>Cybersecurity Attacks</b> (`cybersecurity_attacks.csv`): This dataset
provides details about various cyberattacks, including attack types,
affected systems, and protocols.

<b>AWS Honeypot Logs</b> (`AWS_Honeypot_marx-geo.csv`): A honeypot is a
decoy system designed to attract cyber attackers. This dataset contains
logs of malicious activities targeting an AWS-based honeypot. This data
offers insights into an attackers behaviors and techniques.

<b>Cybersecurity Dataset</b> (`Cybersecurity_Dataset.csv`): This dataset
contains a broader range of cybersecurity-related data, including
network traffic information, attack vectors, and defense mechanisms.

<b>Hacker News Articles</b> (`HN_posts_year_to_Sep_26_2016.csv`): A
collection of posts from Hacker News, a platform where cybersecurity
incidents, techniques, and news are discussed. This dataset provides a
look into real-world relevant cyber attacks occurring globally.

# Initial Look at the Datasets

We first begin by looking at the variables within the datasets to get a
better understanding on which variables can be used for analysis.
Immediately, we can see variables that are of interest including:

    From Cybersecurity Attacks Dataset:
        Source Port, Destination Port, Protocol, Attack Type, Packet Length

    From AWS Honeypot Logs:
        Protocol (proto), Destination Port (dpt), Source Port (spt), Coutry

    From Cybersecurity Dataset:
        Threat Category, Attack Vector, Suggested Defense Mechanism

    From Hacker News Articles Dataset:
        title

These key variables will be explored and analyzed to identify relevant
information. Below is a quick display of variables belonging to each
dataset.

``` r
names(cyber_attacks) %>%
  head(5)
```

    ## [1] "Timestamp"              "Source IP Address"      "Destination IP Address"
    ## [4] "Source Port"            "Destination Port"

``` r
names(aws_attacks) %>%
  head(5)
```

    ## [1] "datetime" "host"     "src"      "proto"    "type"

``` r
names(cyber_dataset) %>%
  head(5)
```

    ## [1] "Threat Category"                 "IOCs (Indicators of Compromise)"
    ## [3] "Threat Actor"                    "Attack Vector"                  
    ## [5] "Geographical Location"

``` r
names(hn_titles) %>%
  head(5)
```

    ## [1] "id"           "title"        "url"          "num_points"   "num_comments"

# Clean and Combine Data for Analysis

The datasets were cleaned and combined to create unified data frames for
analysis. This process involved:

    1. Merging AWS Honeypot Logs and Cybersecurity Attacks
    2. Integrating Geographical Information
    3. Combining Attack Type Data

This combined dataset serves as a foundation for deeper exploration of
attack patterns, network behavior, and geographical trends. The
variables of the combined datasets can be seen below

``` r
df_aws_cyberattacks <- bind_rows(
  aws_attacks %>%
    select(
      Protocol = proto,
      `Source Port` = spt,
      `Destination Port` = dpt
    ) %>%
    mutate(
      Protocol = as.character(Protocol),
      `Source Port` = as.numeric(`Source Port`),
      `Destination Port` = as.numeric(`Destination Port`)
    ),
  
  cyber_attacks %>%
    select(
      Protocol = Protocol,
      `Source Port` = `Source Port`,
      `Destination Port` = `Destination Port`
    ) %>%
    mutate(
      Protocol = as.character(Protocol),
      `Source Port` = as.numeric(`Source Port`),
      `Destination Port` = as.numeric(`Destination Port`)
    )
)
names(df_aws_cyberattacks)
```

    ## [1] "Protocol"         "Source Port"      "Destination Port"

``` r
df_aws_cyberdataset_country <- bind_rows(
  aws_attacks %>%
    select(
      Country = country
    ) %>%
    mutate(
      Country = as.character(Country)
    ),
  
  cyber_dataset %>%
    select(
      Country = `Geographical Location`
    ) %>%
    mutate(
      Country = as.character(Country)
    )
)
names(df_aws_cyberdataset_country)
```

    ## [1] "Country"

``` r
df_cyberdataset_cyberattacks_attack_type <- bind_rows(
  cyber_dataset %>%
    select(
      `Attack Type` = `Threat Category`
    ) %>%
    mutate(
      `Attack Type` = as.character(`Attack Type`)
    ),
  
  cyber_attacks %>%
    select(
      `Attack Type` = `Attack Type`
    ) %>%
    mutate(
      `Attack Type` = as.character(`Attack Type`)
    )
)
names(df_cyberdataset_cyberattacks_attack_type)
```

    ## [1] "Attack Type"

# Protocols and Ports used in Cyber Attacks

Understanding the protocols and ports involved in cyberattacks is
crucial for identifying patterns in network exploitation.

<b>Top Protocols:</b> The most frequently used protocols in cyberattacks
were identified from a unified dataset then visualized using a bar
chart. This analysis shows which specific network protocols are
leveraged by attackers as opposed to other less-frequently used
protocols. Some other popular protocols used in cyberattacks not shown
on this analysis includes `SMTP`, `DHCP`, and `ARP`.

<b>Source and Destination Ports:</b> From the combined datasets, the top
10 source and destination ports that attackers commonly use for
malicious traffic are shown. This is important because it shows that
malicious traffic can target ports that are not commonly used. Protocols
have default ports, for example in the format `Protocol:Port`; the
following default configurations typically are `HTTP:80`, `HTTPS:443`,
`MySQL:3306`, `Telnet:23`, `DNS:53` just to name a few. What this data
tells us is that not enough preventive measures were taken to mitigate
this risk, by leaving unused ports open, attackers have a larger
attack-surface. This can easily be mitigated by configuring proper
firewall rules or “white-listing” specific ports which will deny ingress
and egress traffic from all other non-whitelisted ports.

``` r
protocol_analysis <- df_aws_cyberattacks %>%
  count(`Protocol`, sort = TRUE)

ggplot(protocol_analysis, aes(x = reorder(`Protocol`, n), y = n)) +
  geom_bar(stat = "identity", fill = "steelblue") +
  coord_flip() +
  theme_minimal() +
  labs(
    title = "Top Protocols used in Cyber Attacks",
    x = "Protocol",
    y = "Number of Occurrences"
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-3-1.png)

``` r
source_port_analysis <- df_aws_cyberattacks %>%
  filter(!is.na(`Source Port`)) %>%  
  count(`Source Port`, sort = TRUE) %>%
  head(10)  

ggplot(source_port_analysis, aes(x = reorder(`Source Port`, n), y = n)) +
  geom_bar(stat = "identity", fill = "steelblue") +
  coord_flip() +
  theme_minimal() +
  labs(
    title = "Top 10 Source Ports in Cyber Attacks",
    x = "Source Port",
    y = "Number of Occurrences"
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-3-2.png)

``` r
destination_port_analysis <- df_aws_cyberattacks %>%
  filter(!is.na(`Destination Port`)) %>%
  count(`Destination Port`, sort = TRUE) %>%
  head(10)


ggplot(destination_port_analysis, aes(x = reorder(`Destination Port`, n), y = n)) +
  geom_bar(stat = "identity", fill = "steelblue") +
  coord_flip() +
  theme_minimal() +
  labs(
    title = "Top 10 Destination Ports in Cyber Attacks",
    x = "Destination Port",
    y = "Number of Occurrences"
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-3-3.png)

# Traffic Type Analysis

A breakdown of traffic types in cyberattacks reveals the distribution of
attack vectors. The polar bar chart displays the percentage of
occurrences for each traffic type. This analysis helps identify dominant
attack vectors and prioritize defensive measures aiding in the
development of targeted mitigation strategies. With this knowledge, a
cybersecurity professional is able to pay close attention to this
traffic type and monitor it closely for any anomalies.

``` r
traffic_type_analysis <- cyber_attacks %>%
  count(`Traffic Type`, sort = TRUE) %>%
  mutate(percentage = (n/sum(n))*100)


ggplot(traffic_type_analysis, 
       aes(x = "", y = n, fill = reorder(`Traffic Type`, n))) +
  geom_bar(stat = "identity", width = 1) +
  coord_polar("y", start = 0) +
  theme_minimal() +
  scale_fill_brewer(palette = "Blues") + 
  geom_text(aes(label = sprintf("%s\n%.1f%%", `Traffic Type`, percentage),
                y = cumsum(n) - n/2),
            size = 3) +
  theme(
    axis.text = element_blank(),
    axis.title = element_blank(),
    panel.grid = element_blank(),
    plot.title = element_text(size = 14, face = "bold", hjust = 0.5),
    plot.subtitle = element_text(hjust = 0.5),
    legend.position = "none"
  ) +
  labs(
    title = "Distribution of Traffic Types in Cyber Attacks",
    subtitle = paste("Total observations:", scales::comma(sum(traffic_type_analysis$n)))
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-4-1.png)

# Analyzing Attack Types

From the combined datasets, we notice the most prevalent attack types
including: DDoS, Malware, and Intrusion.

<b>Top Attack Types:</b> Although these 3 attack types are rather close
to each other in terms of popularity, Distributed Denial of Service
`DDoS` ranked at the top. We can assume this to be the case because
`DDoS` is the only attack on here that does not rely on compromising or
“breaking-into” the target asset. Rather, it leverages distributed
computing resources, sometimes referred to as “zombie computers”, that
floods the target with network requests ultimately exhausting the
target’s resources causing it to stall, crash, or completely take it
offline.

`Malware` is still a popular choice as there are many forms of malware
such as spyware, RAT (Remote Access Trojan), Worms (a type of malware
that spreads and infects several computers within a network) just to
name a few.

`Intrusion` is also popular as it relies on exploiting a weakness in the
target system allowing attackers to benefit from the compromise. This
compromise typically leads to some sort of data ex-filtration such as
stealing a website’s database containing usernames, emails, full_name,
credit card information and more.

Other attack types are shown but did not come close to the top 3.
`Phishing` is a popular Social Engineering tactic that directly takes
advantage of the decision making of individuals and/or groups.
`Ransomware` is a very specific and popular type of malware where the
victim will have their data encrypted rendering it obsolete and
inaccessible. The victim will then have to pay a ransom to the attacker
for the decryption key or decryption software.

<b>Total Observations:</b> Each attack type’s contribution to the
overall dataset is annotated with its percentage and the total number of
occurrences across all attack types.

``` r
attack_type_analysis <- df_cyberdataset_cyberattacks_attack_type %>%
  count(`Attack Type`, sort = TRUE) %>%
  mutate(percentage = (n/sum(n))*100)

ggplot(attack_type_analysis, aes(x = reorder(`Attack Type`, n), y = n)) +
  geom_bar(stat = "identity", fill = "steelblue", alpha = 0.8) +
  coord_flip() +
  theme_minimal() +
  scale_y_continuous(
    labels = scales::comma,
    breaks = scales::pretty_breaks(n = 10),  
    expand = expansion(mult = c(0, 0.1))     
  ) +
  geom_text(aes(label = sprintf("%s\n(%.1f%%)", scales::comma(n), percentage)),
            hjust = -0.1,                    
            size = 3) +                     
  theme(
    axis.text = element_text(size = 10),
    axis.title = element_text(size = 12, face = "bold"),
    plot.title = element_text(size = 14, face = "bold"),
    panel.grid.major.y = element_blank(),    
    panel.grid.minor = element_blank()       
  ) +
  labs(
    title = "Attack Types in Cyber Attacks",
    subtitle = paste("Total observations:", scales::comma(sum(attack_type_analysis$n))),
    x = "Attack Type",
    y = "Number of Occurrences"
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-5-1.png)

<h3>
<b> Analyzing Packet sizes by Attack Type </b>
</h3>

This analysis examines packet size characteristics for different attack
types, providing insights into how attackers use network traffic.

<b>Average Packet Length:</b> The polar bar chart illustrates the
average packet size for each attack type. DDoS attacks have the largest
average packet size, reflecting their nature of flooding networks with
large volumes of traffic.

<b>Statistical Summaries:</b> For each attack type, metrics such as
average, median, maximum, and minimum packet lengths were calculated,
showing variations in packet sizes. These metrics help distinguish the
traffic patterns of DDoS, Malware, and Intrusion attacks.

By understanding the variations of packet length, src+dst ports,
protocol, and traffic type in cyberattacks; it may further equip
cyber-defenders with theh knowledge necessary to prevent a system
compromise.

``` r
packet_analysis_by_attacktype <- cyber_attacks %>%
  group_by(`Attack Type`) %>%
  summarise(
    n = n(),
    avg_packet_length = mean(`Packet Length`, na.rm = TRUE),
    med_packet_length = median(`Packet Length`, na.rm = TRUE),
    max_packet_length = max(`Packet Length`, na.rm = TRUE),
    min_packet_length = min(`Packet Length`, na.rm = TRUE),
    .groups = 'drop'
  ) %>%
  arrange(desc(avg_packet_length)) %>%
  mutate(percentage = (n/sum(n))*100)

packet_analysis_by_attacktype
```

    ## # A tibble: 3 × 7
    ##   `Attack Type`     n avg_packet_length med_packet_length max_packet_length
    ##   <chr>         <int>             <dbl>             <dbl>             <dbl>
    ## 1 DDoS          13428              785.               786              1500
    ## 2 Intrusion     13265              781.               785              1500
    ## 3 Malware       13307              778.               777              1500
    ## # ℹ 2 more variables: min_packet_length <dbl>, percentage <dbl>

``` r
ggplot(packet_analysis_by_attacktype, 
       aes(x = "", y = avg_packet_length, 
           fill = reorder(`Attack Type`, avg_packet_length))) +
  geom_bar(stat = "identity", width = 1) +
  coord_polar("y", start = 0) +  
  theme_minimal() +
  scale_fill_brewer(palette = "Blues") +  
  geom_text(aes(label = sprintf("%s\n(%.1f%%)", 
                               scales::comma(avg_packet_length), 
                               percentage)),
            position = position_stack(vjust = 0.5)) +
  theme(
    axis.text = element_text(size = 10),
    axis.title = element_blank(),
    plot.title = element_text(size = 14, face = "bold"),
    legend.title = element_text(size = 12, face = "bold"),
    legend.text = element_text(size = 10),
    panel.grid = element_blank()
  ) +
  labs(
    title = "Average Packet Length by Attack Type",
    subtitle = paste("Total observations:", 
                    scales::comma(sum(packet_analysis_by_attacktype$n))),
    fill = "Attack Type" 
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-6-1.png)

<h3>
<b> Attack Protocol Relationship
</h3>

</b> This analysis explores the relationship between attack types and
the protocols used in executing cyberattacks.

<b>Protocol Distribution by Attack Type:</b> The stacked bar chart shows
the number of protocols for each attack type. This helps identify the
`TCP`, `UDP`, and `ICMP` as protocols of interest because of their
prevalence with specific attacks such as DDoS, Malware, or Intrusion.

<b>Insights:</b> The protocol composition provides valuable insights for
understanding the technical nature of different attack types which helps
in tailoring defense mechanisms to safeguard these communication
mediums.

``` r
attack_protocol_relationship <- cyber_attacks %>%
  count(`Attack Type`, Protocol) %>%
  spread(Protocol, n, fill = 0)

ggplot(attack_protocol_relationship %>% 
       gather(Protocol, Count, -`Attack Type`)) +
  geom_bar(aes(x = `Attack Type`, y = Count, fill = Protocol),
           stat = "identity", position = "stack") +
  theme_minimal() +
  scale_fill_brewer(palette = "Blues") +
  labs(
    title = "Distribution of Protocols by Attack Type",
    subtitle = "Showing the composition of protocols for each attack type",
    x = "Attack Type",
    y = "Count"
  ) +
  geom_text(aes(x = `Attack Type`, y = Count, 
                label = scales::comma(Count), group = Protocol),
            position = position_stack(vjust = 0.5))
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-7-1.png)

<h3>
<b> Top Attack Vectors
</h3>

</b> This analysis identifies the most common attack vectors in the
Cybersecurity Dataset. A bar chart displays the frequency of different
attack vectors (e.g., phishing, brute force, malware). The results
highlight which attack vectors are most prevalent, providing insights
into attacker behavior and common methods of exploitation. Together,
these analyses provide actionable insights into the relationship between
attack types, protocols, and vectors, helping to shape more effective
cybersecurity strategies.

``` r
attack_vector_analysis <- cyber_dataset %>%
  count(`Attack Vector`, sort = TRUE) %>%
  mutate(percentage = (n/sum(n))*100) 

ggplot(attack_vector_analysis, aes(x = reorder(`Attack Vector`, n), y = n)) +
  geom_bar(stat = "identity", fill = "steelblue", alpha = 0.8) +
  coord_flip() +
  theme_minimal() +
  scale_y_continuous(
    labels = scales::comma,
    breaks = scales::pretty_breaks(n = 10),  
    expand = expansion(mult = c(0, 0.1))     
  ) +
  geom_text(aes(label = sprintf("%s\n(%.1f%%)", scales::comma(n), percentage)),
            hjust = -0.1,                    
            size = 3) +                      
  theme(
    axis.text = element_text(size = 10),
    axis.title = element_text(size = 12, face = "bold"),
    plot.title = element_text(size = 14, face = "bold"),
    panel.grid.major.y = element_blank(),    
    panel.grid.minor = element_blank()       
  ) +
  labs(
    title = "Distribution of Attack Vectors in Cyber Attacks",
    subtitle = paste("Total observations:", scales::comma(sum(attack_vector_analysis$n))),
    x = "Attack Vector",
    y = "Number of Occurrences"
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-8-1.png)

# Top Countries Involved in Cyber Attacks

This analysis identifies the top 10 countries contributing to offensive
cyberattacks based on data from the AWS Honeypot and Cybersecurity
Dataset:

<b>Key Insights:</b> The bar chart shows the frequency of attacks
originating from each country while showcasing a trend on prominent
geographical locations involved in cyberattacks. These findings
emphasize the need for global collaboration, policy decisions, and
defense strategies in order to mitigate cyber threats and strengthen
international cybersecurity measures.

``` r
top_countries <- df_aws_cyberdataset_country %>%
  count(`Country`, sort = TRUE) %>%
  head(10)

ggplot(top_countries, aes(x = reorder(`Country`, n), y = n)) +
  geom_bar(stat = "identity", fill = "steelblue") +
  coord_flip() +
  theme_minimal() +
  labs(
    title = "Top 10 Countries involved in Cyber Attacks",
    x = "Country",
    y = "Number of Occurrences"
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-9-1.png)

# Text Mining and Sentiment Analysis in Hacker News

Sentiment and text mining were performed on the Hacker News Articles
dataset to analyze the sentiment and key themes in article titles. The
titles were tokenized into individual words and the analysis was
conducted using Bing Lexicon which categorizes words into a positive or
negative category.

<b>Key Findings:</b> A bar chart visualizes the top 20 words by
sentiment and highlights the most frequently used positive and negative
terms in article titles. Words associated with negative sentiment often
reflect concerns or warnings, while positive terms suggest opportunities
or solutions.

``` r
tidy_titles <- hn_titles %>%
  unnest_tokens(word, title) %>%
  anti_join(stop_words)
```

    ## Joining with `by = join_by(word)`

``` r
title_sentiments <- tidy_titles %>%
  inner_join(get_sentiments("bing"), relationship = "many-to-many") %>%
  count(word, sentiment, sort=T)
```

    ## Joining with `by = join_by(word)`

``` r
ggplot(head(title_sentiments, 20), 
       aes(x = reorder(word, n), y = n, fill = sentiment)) +
  geom_col() +
  coord_flip() +
  theme_minimal() +
  labs(
    title = "Top Words by Sentiment in Hacker News Titles",
    x = "Word",
    y = "Count"
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-10-1.png)

<h3>
<b> Word Cloud From Negative words found in Sentiment Analysis</b>
</h3>

A word cloud was generated to visualize the most frequent negative words
extracted from sentiment analysis of Hacker News titles. The word cloud
highlights terms commonly associated with negative sentiments. Prominent
words such as “cloud,” “breach,” and “attack” indicate significant
concerns about cloud-based assets and cyber threats.

<b>Insights:</b> The frequent mention of “cloud” suggests that cloud
infrastructure is a primary target for cyberattacks as many
organizations have moved to cloud based solutions. Other terms in the
word cloud point to specific threats and vulnerabilities. This word
cloud provides a visual summary of negative sentiment in Hacker News
articles which serves as a guide on focus areas for research and
defense.

``` r
negative_words <- title_sentiments %>%
  filter(sentiment == "negative") %>%
  arrange(desc(n))

wordcloud(words = negative_words$word, 
          freq = negative_words$n, 
          max.words = 100,          
          random.order = FALSE,     
          colors = brewer.pal(8, "Dark2"),  
          scale = c(3, 0.5))      

title(main = "Negative Words in Hacker News Titles")
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-11-1.png)

<h3>
<b>Finding the Attack Type frequency in Hacker News article titles</b>
</h3>

This analysis showcases a bar chart related to the frequency of key
attack types that were determined in the analysis above (e.g., DDoS,
Malware, Phishing, Intrusion, Ransomware). The distribution of attack
type mentions shows a trend into which cybersecurity issues are most
frequent in news worthy articles. The visualization and data provide a
clear view of how different attack types are represented on Hacker News.

``` r
find_security_terms <- function(text, term) {
  sum(grepl(term, text, ignore.case=T))
}


security_terms <- data.frame(
  term = c("DDoS", "malware", "phishing", "intrusion", "ransomware"),
  count = c(
    find_security_terms(hn_titles$title, "DDoS"),
    find_security_terms(hn_titles$title, "malware"),
    find_security_terms(hn_titles$title, "phishing"),
    find_security_terms(hn_titles$title, "intrusion"),
    find_security_terms(hn_titles$title, "ransomware")
  )
)

security_terms <- security_terms %>%
  mutate(percentage = (count/sum(count))*100)

ggplot(security_terms, aes(x = reorder(term, count), y = count)) +
  geom_bar(stat = "identity", fill = "steelblue", alpha = 0.8) +
  coord_flip() +
  theme_minimal() +
  scale_y_continuous(
    labels = scales::comma,
    breaks = scales::pretty_breaks(n = 10),
    expand = expansion(mult = c(0, 0.1))
  ) +
  geom_text(aes(label = sprintf("%s\n(%.1f%%)", scales::comma(count), percentage)),
            hjust = -0.1,
            size = 3) +
  theme(
    axis.text = element_text(size = 10),
    axis.title = element_text(size = 12, face = "bold"),
    plot.title = element_text(size = 14, face = "bold"),
    panel.grid.major.y = element_blank(),
    panel.grid.minor = element_blank()
  ) +
  labs(
    title = "Frequency of Attack Type Terms in Titles",
    subtitle = paste("Total observations:", scales::comma(sum(security_terms$count))),
    x = "Attack Types",
    y = "Number of Occurrences"
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-12-1.png)

<h3>
<b>Finding The Frequency of Country Mentions in Hacker News Titles</b>
</h3>

This analysis examines the frequency of country mentions in Hacker News
article titles. The bar chart shows the frequency of mentions for
selected countries (e.g., China, United States, Japan, Iran) in the
titles. Here we can see that the United States and China are mentioned
most frequently. These findings highlight regions that attract the most
attention in cybersecurity events and how frequently specific countries
are mentioned in relation to cybersecurity topics

``` r
find_country_terms <- function(text, term) {
  sum(grepl(term, text, ignore.case=T))
}

country_terms <- data.frame(
  term = c("China", "United States", "Japan", "Iran"),
  count = c(
    find_country_terms(hn_titles$title, "China|Chinese"),
    find_country_terms(hn_titles$title, "United States|USA|U.S.|America|American"),
    find_country_terms(hn_titles$title, "Japan|Japanese"),
    find_country_terms(hn_titles$title, "Iran|Iranian")
  )
)

country_terms <- country_terms %>%
  mutate(percentage = (count/sum(count))*100)

ggplot(country_terms, aes(x = reorder(term, count), y = count)) +
  geom_bar(stat = "identity", fill = "steelblue", alpha = 0.8) +
  coord_flip() +
  theme_minimal() +
  scale_y_continuous(
    labels = scales::comma,
    breaks = scales::pretty_breaks(n = 10),
    expand = expansion(mult = c(0, 0.1))
  ) +
  geom_text(aes(label = sprintf("%s\n(%.1f%%)", scales::comma(count), percentage)),
            hjust = -0.1,
            size = 3) +
  theme(
    axis.text = element_text(size = 10),
    axis.title = element_text(size = 12, face = "bold"),
    plot.title = element_text(size = 14, face = "bold"),
    panel.grid.major.y = element_blank(),
    panel.grid.minor = element_blank()
  ) +
  labs(
    title = "Frequency of Country Mentions in Hacker News Titles",
    subtitle = paste("Total observations:", scales::comma(sum(country_terms$count))),
    x = "Country",
    y = "Number of Mentions"
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-13-1.png)

# Random Forests and Predicting

A Random Forest model was implemented to predict cyberattack types based
on selected features from the cyber_attacks dataset.

<b>Feature Selection:</b> Variables commonly associated with
non-predictive or redundant information (e.g., IP addresses, timestamps,
payload data) were excluded so that meaningful predictors like Packet
Length, Traffic Type, and Severity Level could be used.

``` r
cyber_data_test <- cyber_attacks %>%
  select(-Timestamp, 
         -`Source IP Address`, 
         -`Destination IP Address`, 
         -`Payload Data`, 
         -`Malware Indicators`, 
         -`Alerts/Warnings`, 
         -`Attack Signature`, 
         -`Action Taken`, 
         -`IDS/IPS Alerts`, 
         -`Proxy Information`,
         -`Firewall Logs`, 
         -`Geo-location Data`, 
         -`Log Source`, 
         -`Device Information`, 
         -`Network Segment`, 
         -`User Information`) %>%
  rename(
    Source_Port = `Source Port`, 
    Destination_Port = `Destination Port`, 
    Attack_Type = `Attack Type`,
    Packet_Length = `Packet Length`,
    Traffic_Type = `Traffic Type`,
    Anomaly_Scores = `Anomaly Scores`,
    Severity_Level = `Severity Level`, 
    Packet_Type = `Packet Type`
    ) %>%
  drop_na()

names(cyber_data_test)
```

    ## [1] "Source_Port"      "Destination_Port" "Protocol"         "Packet_Length"   
    ## [5] "Packet_Type"      "Traffic_Type"     "Anomaly_Scores"   "Attack_Type"     
    ## [9] "Severity_Level"

<h3>
<b>Random Forest and Predictive Model</b>
</h3>

<b>Model Implementation:</b> The dataset was split into training (75%)
and testing (25%) subsets. The Random Forest model was trained using
1,000 trees (`ntree = 1000`) and 4 features per split (`mtry = 4`).

<b>Performance Insights:</b> The Out-of-Bag (OOB) error rate was 67.25%,
indicating that predicting attack types from the available data is
challenging. This high error rate suggests that cyberattacks may be
difficult to tell apart from normal traffic due to them containing
similar features or well-masked malicious behavior.

The results highlight how complex it is to predict a cyberattack. This
is evidence that there is a need for robust data, advanced modeling
techniques, and well trained professionals with the knowledge necessary
to implement defense mechanisims.

``` r
set.seed(123)
sample = sample.split(seq(1:nrow(cyber_data_test)), SplitRatio = 0.75)
cyber_train <- subset(cyber_data_test, sample == TRUE)
cyber_test <- subset(cyber_data_test, sample == FALSE)
rf_model <- randomForest(
  as.factor(Attack_Type) ~ .,  
  data = cyber_train,
  mtry = 4,                      
  ntree = 1000                   
  )

print(rf_model)
```

    ## 
    ## Call:
    ##  randomForest(formula = as.factor(Attack_Type) ~ ., data = cyber_train,      mtry = 4, ntree = 1000) 
    ##                Type of random forest: classification
    ##                      Number of trees: 1000
    ## No. of variables tried at each split: 4
    ## 
    ##         OOB estimate of  error rate: 67.25%
    ## Confusion matrix:
    ##           DDoS Intrusion Malware class.error
    ## DDoS      3388      3291    3359   0.6624826
    ## Intrusion 3333      3179    3426   0.6801167
    ## Malware   3431      3335    3258   0.6749800

# Conclusion

The rise in sophisticated cyber threats shows the need for more
proactive security measures and data-driven decision-making in order to
effectively predict, prevent, and respond to attacks.

<b>Threat Categories and Defense Mechanisms:</b> An analysis of the
relationship between threat categories and suggested defense mechanisms
provides valuable insights into how organizations can address specific
threats. Threat categories like malware and DDoS attacks often have
defined defense mechanisms that should be incorporated into any
organization’s defensive approach.

<b>Final Thoughts for Security Strategies:</b> Organizations must adopt
what the industry calls “Defense in Depth” which is a layered defense
mechanism that focuses on integrating security via people, processes,
and technology at various levels of the organization. By leveraging data
analysis, we can refine and prioritize defenses which can significantly
enhance the organization’s resilience against evolving cyberattacks.

``` r
threatcat_defensemech_relationship <- cyber_dataset %>% 
  count(`Threat Category`, `Suggested Defense Mechanism`) %>% 
  spread(`Suggested Defense Mechanism`, n, fill = 0)

ggplot(threatcat_defensemech_relationship %>% 
       gather(`Suggested Defense Mechanism`, Count, -`Threat Category`)) +
  geom_bar(aes(x = `Threat Category`, y = Count, 
               fill = `Suggested Defense Mechanism`),
           stat = "identity", 
           position = "stack") +
  theme_minimal() +
  scale_fill_brewer(palette = "Blues") +
  labs(
    title = "Distribution of Defense Mechanisms by Threat Category",
    subtitle = "Showing suggested defenses for each threat category",
    x = "Threat Category",
    y = "Count"
  ) +
  geom_text(aes(x = `Threat Category`, y = Count, 
                label = scales::comma(Count), 
                group = `Suggested Defense Mechanism`),
            position = position_stack(vjust = 0.5)) +
  theme(
    axis.text.x = element_text(angle = 45, hjust = 1),
    legend.position = "right"
  )
```

![](Final_Project-copy_files/figure-markdown_github/unnamed-chunk-16-1.png)
