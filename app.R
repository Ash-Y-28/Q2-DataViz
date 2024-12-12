# Load necessary libraries
library(shiny)
library(ggplot2)
library(ggridges)
library(gganimate)
library(dplyr)
library(reshape2)
library(stringr)
library(viridis)

# Define UI
ui <- fluidPage(
  titlePanel("Interactive Animated Visualizations"),

  # Add tabs for multiple visualizations
  tabsetPanel(
    tabPanel(
      "Ridge Plot Animation",
      sidebarLayout(
        sidebarPanel(
          helpText("Visualize the evolving bandwidth distribution by attack type."),
          sliderInput("fps_ridge", "Frames Per Second", min = 1, max = 30, value = 10),
          sliderInput("nframes_ridge", "Number of Frames", min = 50, max = 200, value = 100)
        ),
        mainPanel(
          imageOutput("animatedRidgePlot")
        )
      )
    ),
    tabPanel(
      "Bar Chart Race Animation",
      sidebarLayout(
        sidebarPanel(
          helpText("View the ranking of attack types by bandwidth over time."),
          sliderInput("fps_bar", "Frames Per Second", min = 1, max = 30, value = 10),
          sliderInput("nframes_bar", "Number of Frames", min = 50, max = 200, value = 100)
        ),
        mainPanel(
          imageOutput("animatedBarChart")
        )
      )
    ),
    tabPanel(
      "Heatmap Animation",
      sidebarLayout(
        sidebarPanel(
          helpText("Analyze the relationship between flow duration bins and attack types."),
          sliderInput("fps_heatmap", "Frames Per Second", min = 1, max = 30, value = 5),
          sliderInput("nframes_heatmap", "Number of Frames", min = 50, max = 200, value = 100)
        ),
        mainPanel(
          imageOutput("animatedHeatmap")
        )
      )
    ),
    tabPanel(
      "Scatter Plot Animation",
      sidebarLayout(
        sidebarPanel(
          helpText("Discover unique patterns of attacks using scatter plot animation."),
          sliderInput("fps_scatter", "Frames Per Second", min = 1, max = 30, value = 5),
          sliderInput("nframes_scatter", "Number of Frames", min = 50, max = 200, value = 50)
        ),
        mainPanel(
          imageOutput("animatedScatterPlot")
        )
      )
    ),
    tabPanel(
      "Time-Series Animation",
      sidebarLayout(
        sidebarPanel(
          helpText("Explore bandwidth variations across attack types over flow duration."),
          sliderInput("fps_time", "Frames Per Second", min = 1, max = 30, value = 10),
          sliderInput("nframes_time", "Number of Frames", min = 100, max = 500, value = 500)
        ),
        mainPanel(
          imageOutput("animatedTimeSeries")
        )
      )
    )
  )
)

# Define server logic
server <- function(input, output, session) {

  # Ridge plot animation
  output$animatedRidgePlot <- renderImage({
    data_ridge <- data %>%
      filter(flow_duration > 0) %>%
      filter(!grepl("^(MQTT|NMAP|Thing_Speak|Wipro)", Attack_type, ignore.case = TRUE)) %>%
      mutate(
        log_payload = log10(payload_bytes_per_second + 1),
        log_iat = log10(flow_iat.avg + 1),
        iat_bin = cut(log_iat, breaks = 5),
        Attack_type = as.factor(Attack_type)  # Ensure Attack_type is a factor
      )

    ridge_plot <- ggplot(data_ridge, aes(x = log_payload, y = Attack_type, fill = Attack_type)) +
      geom_density_ridges(alpha = 0.8, scale = 1) +
      labs(
        title = "Bandwidth vs. Inter-Arrival Time",
        subtitle = "Evolving Bandwidth Distribution by Attack Type",
        x = "Log of Bandwidth (bytes per second)",
        y = "Attack Types"
      ) +
      theme_minimal() +
      theme(legend.position = "none")

    animated_ridge_plot <- ridge_plot +
      transition_states(iat_bin, transition_length = 2, state_length = 1) +
      labs(title = "Bandwidth Distribution Across Attack Types",
           subtitle = "Inter-Arrival Time Range: {closest_state}",
           x = "Log of Bandwidth (bytes per second)",
           y = "Attack Types") +
      enter_fade() +
      exit_fade()

    anim_file <- tempfile(fileext = ".gif")
    animate(animated_ridge_plot, nframes = input$nframes_ridge, fps = input$fps_ridge, width = 600, height = 400, renderer = gifski_renderer(anim_file))

    list(src = anim_file, contentType = "image/gif", width = 600, height = 400)
  }, deleteFile = TRUE)

  # Bar chart race animation
  output$animatedBarChart <- renderImage({
    bar_data <- data %>%
      filter(flow_duration > 0 & payload_bytes_per_second > 0) %>%
      filter(!grepl("^(MQTT|NMAP|Thing_Speak|Wipro|metasploit_Brute_Force_SSH)", Attack_type, ignore.case = TRUE)) %>%
      group_by(Attack_type) %>%
      summarize(total_bandwidth = sum(log10(payload_bytes_per_second + 1), na.rm = TRUE)) %>%
      arrange(desc(total_bandwidth)) %>%
      mutate(rank = row_number())

    animated_bar <- ggplot(bar_data, aes(x = reorder(Attack_type, -total_bandwidth), y = total_bandwidth, fill = Attack_type)) +
      geom_bar(stat = "identity", alpha = 0.8) +
      geom_text(aes(label = round(total_bandwidth, 2)), hjust = -0.2, size = 4) +
      coord_flip() +
      expand_limits(y = 0) +
      scale_y_continuous(expand = expansion(mult = c(0.05, 0.1))) +
      labs(
        title = "Log-Transformed Ranking of Attack Types by Bandwidth",
        subtitle = "Top Attack Types by Bandwidth Contribution",
        x = "Attack Type",
        y = "Log of Total Bandwidth (bytes per second)",
        fill = "Attack Type"
      ) +
      theme_minimal() +
      theme(
        axis.text.x = element_text(angle = 45, hjust = 1),
        axis.text.y = element_text(size = 10)
      ) +
      transition_states(rank, transition_length = 2, state_length = 1) +
      ease_aes('linear')

    anim_file <- tempfile(fileext = ".gif")
    animate(animated_bar, nframes = input$nframes_bar, fps = input$fps_bar, width = 1200, height = 800, renderer = gifski_renderer(anim_file))

    list(src = anim_file, contentType = "image/gif", width = 1200, height = 800)
  }, deleteFile = TRUE)

  # Heatmap animation
  output$animatedHeatmap <- renderImage({
    heatmap_data <- data %>%
      filter(flow_duration > 0 & payload_bytes_per_second > 0) %>%
      filter(!grepl("^(MQTT|NMAP|Thing_Speak|Wipro)", Attack_type, ignore.case = TRUE)) %>%
      mutate(flow_bin = cut(flow_duration, breaks = 5)) %>%
      group_by(Attack_type, flow_bin) %>%
      summarize(mean_bandwidth = mean(log10(payload_bytes_per_second), na.rm = TRUE), .groups = "drop") %>%
      melt(id.vars = c("Attack_type", "flow_bin"))

    animated_heatmap <- ggplot(heatmap_data, aes(x = flow_bin, y = Attack_type, fill = value)) +
      geom_tile(color = "white") +
      geom_text(aes(label = round(value, 2)), color = "black", size = 3) +
      scale_fill_gradient(
        low = "lightblue",
        high = "orange",
        name = "Log Bandwidth\n(bytes/sec)",
        labels = function(x) paste0("~10^", round(x, 1))
      ) +
      labs(
        title = "Heatmap of Log-Transformed Metrics by Attack Type",
        subtitle = "Flow Duration Bin: {closest_state}",
        x = "Flow Duration Bin",
        y = "Attack Type",
        fill = "Log Value"
      ) +
      theme_minimal() +
      theme(
        axis.text.x = element_blank(),
        axis.ticks.x = element_blank()
      ) +
      transition_states(flow_bin, transition_length = 2, state_length = 1) +
      ease_aes('linear')

    anim_file <- tempfile(fileext = ".gif")
    animate(animated_heatmap, nframes = input$nframes_heatmap, fps = input$fps_heatmap, width = 800, height = 600, renderer = gifski_renderer(anim_file))

    list(src = anim_file, contentType = "image/gif", width = 800, height = 600)
  }, deleteFile = TRUE)

  # Scatter plot animation
  output$animatedScatterPlot <- renderImage({
    data_scatter <- data %>%
      filter(flow_duration > 0,
             !str_starts(Attack_type, regex("^(MQTT|NMAP|Thing_Speak|Wipro)", ignore_case = TRUE))) %>%
      group_by(Attack_type) %>%
      mutate(log_flow_duration = log10(flow_duration),
             log_payload = log10(payload_bytes_per_second + 1))

    animated_plot <- ggplot(data_scatter, aes(x = log_flow_duration,
                                              y = log_payload,
                                              color = Attack_type)) +
      geom_point(alpha = 0.7) +
      labs(title = "Unique Patterns of Attacks",
           x = "Log of Flow Duration",
           y = "Log of Payload (bytes per second)") +
      theme_minimal() +
      theme(legend.position = "bottom") +
      transition_states(Attack_type, transition_length = 2, state_length = 1) +
      enter_fade() +
      exit_shrink() +
      ease_aes('linear')

    anim_file <- tempfile(fileext = ".gif")
    animate(animated_plot, nframes = input$nframes_scatter, fps = input$fps_scatter, width = 400, height = 400, renderer = gifski_renderer(anim_file))

    list(src = anim_file, contentType = "image/gif", width = 400, height = 400)
  }, deleteFile = TRUE)

  # Time-series animation
  output$animatedTimeSeries <- renderImage({
    time_data <- data %>%
      filter(payload_bytes_per_second > 0 & flow_duration > 0 & flow_duration <= 100) %>%
      filter(!grepl("^(MQTT|NMAP|Thing_Speak|Wipro)", Attack_type, ignore.case = TRUE)) %>%
      mutate(
        log_bandwidth = log10(payload_bytes_per_second)
      )

    animated_flow_lines <- ggplot(time_data, aes(x = flow_duration, y = log_bandwidth, color = Attack_type, group = Attack_type)) +
      geom_line(size = 1, alpha = 0.8) +
      labs(
        title = "Bandwidth Variations Across Attack Types",
        subtitle = "Flow Duration: {frame_along}",
        x = "Flow Duration",
        y = "Log Bandwidth (bytes per second)",
        color = "Attack Type"
      ) +
      scale_color_viridis_d() +
      theme_minimal() +
      theme(
        axis.text.x = element_text(angle = 45, hjust = 1),
        legend.position = "bottom"
      ) +
      coord_cartesian(xlim = c(0, 50)) +
      transition_reveal(flow_duration)

    anim_file <- tempfile(fileext = ".gif")
    animate(animated_flow_lines, nframes = input$nframes_time, fps = input$fps_time, width = 1200, height = 800, renderer = gifski_renderer(anim_file))

    list(src = anim_file, contentType = "image/gif", width = 1200, height = 800)
  }, deleteFile = TRUE)
}

# Run the Shiny app
shinyApp(ui = ui, server = server)
