library(readr)
library(tidyverse)

cyber_attacks <- read_csv("archive/cybersecurity_attacks.csv")
aws_attacks <- read_csv("archive/AWS_Honeypot_marx-geo.csv")
cyber_dataset <- read_csv("archive/Cybersecurity_Dataset.csv")
hn_titles <- read_csv("archive/HN_posts_year_to_Sep_26_2016.csv")


str(cyber_attacks)
cat("Dimensions of datasets:\n")
cat("cyber_attacks:", dim(cyber_attacks), "\n")

names(cyber_attacks)
names(aws_attacks)
names(cyber_dataset)
names(hn_titles)


source_port_analysis <- cyber_attacks %>%
  count(`Source Port`, sort = TRUE) %>%
  head(10)  # Top 10 source ports

ggplot(source_port_analysis, aes(x = reorder(`Source Port`, n), y = n)) +
  geom_bar(stat = "identity", fill = "steelblue") +
  coord_flip() +
  theme_minimal() +
  labs(
    title = "Top 10 Source Ports in Cyber Attacks",
    x = "Source Port",
    y = "Number of Occurrences"
  )


protocol_analysis <- cyber_attacks %>%
  count(`Protocol`, sort = TRUE) %>%
  head(10)  # Top 10 source ports

attack_type_analysis <- cyber_attacks %>%
  count(`Attack Type`, sort = TRUE) %>%
  head(10)

traffic_type_analysis <- cyber_attacks %>%
  count(`Traffic Type`, sort = TRUE) %>%
  head(10)

ggplot(traffic_type_analysis, aes(x = reorder(`Traffic Type`, n), y = n)) +
  geom_bar(stat = "identity", fill = "blue") +
  coord_flip() +
  theme_minimal() +
  labs(
    title = "Top Traffic Types in Cyber Attacks",
    x = "Traffic Type",
    y = "Number of Occurrences"
  )



ggplot(attack_type_analysis, aes(x = reorder(`Attack Type`, n), y = n)) +
  geom_bar(stat = "identity", fill = "blue") +
  coord_flip() +
  theme_minimal() +
  labs(
    title = "Top Cyber Attacks",
    x = "Attack Type",
    y = "Number of Occurrences"
  )

attack_protocol_relationship <- cyber_attacks %>%
  count(`Attack Type`, Protocol) %>%
  spread(Protocol, n, fill = 0)


packet_analysis_by_attacktype <- cyber_attacks %>%
  group_by(`Attack Type`) %>%
  summarise(
    avg_packet_length = mean(`Packet Length`, na.rm = TRUE),
    med_packet_length = median(`Packet Length`, na.rm = TRUE),
    max_packet_length = max(`Packet Length`, na.rm = TRUE),
    min_packet_length = min(`Packet Length`, na.rm = TRUE),
    .groups = 'drop'
  ) %>%
  arrange(desc(avg_packet_length))



#=============================Cyber Dataset ======================
geo_location_analysis <- cyber_dataset %>%
  count(`Geographical Location`, sort = TRUE) %>%
  head(10) 


#=======================Combined Data sets=====================

# Version with explicit type conversion
df_aws_cyberattacks <- bind_rows(
  # aws_attacks portion
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
  
  # cyber_attacks portion
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


#=================

attack_patterns <- cyber_attacks %>%
  select(`Packet Length`, `Anomaly Scores`, Protocol, `Traffic Type`) %>%
  scale()
km_attacks <- kmeans(attack_patterns, centers = 4, nstart = 25)


attack_clusters <- cyber_attacks %>%
  mutate(cluster = km_attacks$cluster) %>%
  group_by(cluster) %>%
  summarise(
    avg_packet_length = mean(`Packet Length`),
    avg_anomaly_score = mean(`Anomaly Scores`),
    count = n(),
    dominant_attack = names(which.max(table(`Attack Type`)))
    )
attack_clusters


#====================

> cyber_data_test <- cyber_attacks %>%
  +     select(-Timestamp, -`Source IP Address`, -`Destination IP Address`, 
               +            -`Payload Data`, -`Malware Indicators`, -`Alerts/Warnings`, 
               +            -`Attack Signature`, -`Action Taken`, -`IDS/IPS Alerts`, 
               +            -`Proxy Information`, -`potential_anomaly`, -`Firewall Logs`, 
               +            -`Geo-location Data`, -`Log Source`, -`Device Information`, 
               +            -`Network Segment`, -`User Information`) %>%
  +     rename(
    +         Source_Port = `Source Port`,
    +         Destination_Port = `Destination Port`,
    +         Attack_Type = `Attack Type`,
    +         Packet_Length = `Packet Length`,
    +         Traffic_Type = `Traffic Type`,
    +         Anomaly_Scores = `Anomaly Scores`,
    +         Severity_Level = `Severity Level`, 
    +         Packet_Type = `Packet Type`
    +     ) %>%
  +     drop_na()
> set.seed(123)
> sample = sample.split(seq(1:nrow(cyber_data_test)), SplitRatio = 0.75)
> cyber_train <- subset(cyber_data_test, sample == TRUE)
> cyber_test <- subset(cyber_data_test, sample == FALSE)
> rf_model <- randomForest(
  +     as.factor(Attack_Type) ~ .,  
  +     data = cyber_train,
  +     mtry = 4,                      
  +     ntree = 1000                   
  + )
> print(rf_model)




threatcat_defensemech_relationship <- cyber_dataset %>% 
  count(`Threat Category`, `Suggested Defense Mechanism`) %>% 
  spread(`Suggested Defense Mechanism`, n, fill=0)


ggplot(threatcat_defensemech_relationship %>% 
         gather(`Suggested Defense Mechanism`, -`Threat Category`)) +
  geom_bar(aes(x = `Threat Category`, y = Count, fill = `Suggested Defense Mechanism`),
           stat = "identity", position = "stack") +
  theme_minimal() +
  scale_fill_brewer(palette = "Blues") +
  labs(
    title = "Distribution of Protocols by Attack Type",
    subtitle = "Showing the composition of protocols for each attack type",
    x = "Attack Type",
    y = "Count"
  ) +
  geom_text(aes(x = `Threat Category`, y = Count, 
                label = scales::comma(Count), group = `Suggested Defense Mechanism`),
            position = position_stack(vjust = 0.5))

