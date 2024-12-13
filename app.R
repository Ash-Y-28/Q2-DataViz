# Load necessary libraries
library(shiny)
library(ggplot2)
library(gganimate)
library(dplyr)
library(stringr)
library(ggridges)
library(here)
library(readr)
library(shinythemes)
library(shinycssloaders)

# Load the data
data <- read_csv(here("data.csv"))

# Define UI
ui <- fluidPage(
  theme = shinytheme("darkly"),  # Applying the chosen theme

  tags$head(tags$style(HTML("

    .hover-image {
      transition: all 0.3s ease-in-out;
      box-shadow: 0px 0px 0px transparent;
    }

    .hover-image:hover {
      transform: translateY(-20px);
      box-shadow: 0px 15px 30px rgba(50, 205, 50, 0.8);
    }

    .hover-text {
      transition: all 0.3s ease-in-out;
      text-shadow: 0px 0px 0px transparent;
      color: white; /* Default color */
    }

    .hover-text:hover {
      transform: translateY(-5px); /* Lift the text up */
      text-shadow: 2px 2px 5px rgba(0, 255, 0, 0.5); /* Green shadow */
      color: #34C759; /* Change text color to green */
    }
  "))),

  titlePanel(
    div("Interactive Animated Visualizations", class = "hover-text")
  ),

  # Add tabs for multiple visualizations
  tabsetPanel(
    tabPanel(
      "Scatter Plot Animation",
      fluidRow(
        column(
          width = 12,
          style = "display: flex; flex-direction: column; align-items: center; justify-content: center; margin-top: 50px;",
          div(
            class = "hover-text",
            style = "text-align: center; margin-bottom: 20px;",
            h4("Discover unique patterns of attacks using scatter plot animation.")
          ),
          div(
            class = "hover-image",
            style = "text-align: center; margin-top: 50px;",
            imageOutput("animatedScatterPlot", height = "500px")
          )
        )
      )
    ),
    tabPanel(
      "Ridge Plot Animation",
      fluidRow(
        column(
          width = 12,
          div(
            class = "hover-text",
            style = "display: flex; flex-direction: column; align-items: center; justify-content: center; margin-top: 50px;",
            h4("Visualize the evolving bandwidth distribution by attack type.",
               style = "text-align: center; margin-bottom: 20px;"),
            div(
              class = "hover-image",
              style = "text-align: center; margin-top: 50px;",
              imageOutput("animatedRidgePlot", height = "500px")
            )
          )
        )
      )
    ),
    tabPanel(
      "Bar Chart Race Animation",
      fluidRow(
        column(
          width = 12,
          div(
            class = "hover-text",
            style = "display: flex; flex-direction: column; align-items: center; justify-content: center; margin-top: 50px;",
            h4("View the ranking of attack types by bandwidth over time.",
               style = "text-align: center; margin-bottom: 20px;"),
            div(
              class = "hover-image",
              style = "text-align: center; margin-top: 50px;",
              imageOutput("animatedBarChart", height = "500px")
            )
          )
        )
      )
    ),
    tabPanel(
      "Time-Series Animation",
      fluidRow(
        column(
          width = 12,
          div(
            class = "hover-text",
            style = "display: flex; flex-direction: column; align-items: center; justify-content: center; margin-top: 50px;",
            h4("Explore bandwidth variations across attack types over flow duration.",
               style = "text-align: center; margin-bottom: 20px;"),
            div(
              class = "hover-image",
              style = "text-align: center; margin-top: 50px;",
              imageOutput("animatedTimeSeries", height = "500px")
            )
          )
        )
      )
    )
  )
)

# Define server logic
server <- function(input, output, session) {

  # Scatter plot animation
  output$animatedScatterPlot <- renderImage({
    data_scatter <- data %>%
      filter(flow_duration > 0) %>%
      filter(!str_starts(Attack_type, regex("^NMAP", ignore_case = TRUE))) %>%
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
    animate(animated_plot, nframes = 75, fps = 10, width = 800, height = 600, renderer = gifski_renderer(anim_file))

    list(src = anim_file, contentType = "image/gif", width = 800, height = 600)
  }, deleteFile = TRUE)

  # Ridge plot animation
  output$animatedRidgePlot <- renderImage({
    data_ridge <- data %>%
      filter(flow_duration > 0) %>%
      filter(!str_starts(Attack_type, regex("^NMAP", ignore_case = TRUE))) %>%
      mutate(log_payload = log10(payload_bytes_per_second + 1),
             log_iat = log10(flow_iat.avg + 1),
             iat_bin = cut(log_iat, breaks = 5))

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
    animate(animated_ridge_plot, nframes = 75, fps = 10, width = 800, height = 600, renderer = gifski_renderer(anim_file))

    list(src = anim_file, contentType = "image/gif", width = 800, height = 600)
  }, deleteFile = TRUE)

  # Bar chart race animation
  output$animatedBarChart <- renderImage({
    bar_data <- data %>%
      filter(flow_duration > 0 & payload_bytes_per_second > 0) %>%
      filter(!str_starts(Attack_type, regex("^NMAP|Metasploit_Brute_Force_SSH", ignore_case = TRUE))) %>%
      group_by(Attack_type) %>%
      summarize(total_bandwidth = sum(log10(payload_bytes_per_second + 1), na.rm = TRUE)) %>%
      arrange(desc(total_bandwidth)) %>%
      mutate(rank = row_number())

    animated_bar <- ggplot(bar_data, aes(x = reorder(Attack_type, -total_bandwidth), y = total_bandwidth, fill = Attack_type)) +
      geom_bar(stat = "identity", alpha = 0.8) +
      geom_text(aes(label = round(total_bandwidth, 2)), hjust = -0.2, size = 4) +
      coord_flip() +
      expand_limits(y = c(0, max(bar_data$total_bandwidth) * 1.1)) +
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
    animate(animated_bar, nframes = 75, fps = 10, width = 800, height = 600, renderer = gifski_renderer(anim_file))

    list(src = anim_file, contentType = "image/gif", width = 800, height = 600)
  }, deleteFile = TRUE)

  # Time-series animation
  output$animatedTimeSeries <- renderImage({
    time_data <- data %>%
      filter(payload_bytes_per_second > 0 & flow_duration > 0 & flow_duration <= 100) %>%
      filter(!str_starts(Attack_type, regex("^NMAP", ignore_case = TRUE))) %>%
      group_by(Attack_type) %>%
      slice(seq(1, n(), by = 5)) %>%  # Downsample data
      mutate(log_bandwidth = log10(payload_bytes_per_second))

    animated_flow_lines <- ggplot(time_data, aes(x = flow_duration, y = log_bandwidth, color = Attack_type, group = Attack_type)) +
      geom_line(size = 1, alpha = 0.8) +
      labs(
        title = "Bandwidth Variations Across Attack Types",
        subtitle = "Flow Duration: {frame_along}",
        x = "Flow Duration",
        y = "Log Bandwidth (bytes per second)",
        color = "Attack Type"
      ) +
      scale_color_brewer(palette = "Set1") +
      theme_minimal() +
      theme(
        axis.text.x = element_text(angle = 45, hjust = 1),
        legend.position = "bottom"
      ) +
      coord_cartesian(xlim = c(0, 100)) +
      transition_reveal(flow_duration)

    anim_file <- tempfile(fileext = ".gif")
    animate(animated_flow_lines, nframes = 75, fps = 10, width = 800, height = 600, renderer = gifski_renderer(anim_file))

    list(src = anim_file, contentType = "image/gif", width = 800, height = 600)
  }, deleteFile = TRUE)
}

# Run the Shiny app
shinyApp(ui = ui, server = server)