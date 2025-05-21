package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/a-h/templ"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"ttwoforks.com/encrypt/web/templates"
)

var logger zerolog.Logger

func main() {
	e := echo.New()
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	e.Use(ZerologMiddleware(logger))

	e.GET("/", func(c echo.Context) error {
		return Render(c, 200, templates.MainTempl())
	})

	e.POST("/", func(c echo.Context) error {
		e, err := encrypt(c)
		if err != nil {
			log.Logger.Error().Msgf("Error Encrypting: %v", err)
			return c.String(http.StatusTeapot, "blarg")
		}
		return Render(c, 200, templates.Encrypted(e))
	})

	e.POST("/format-yaml", func(c echo.Context) error {
		b, err := formatYAMLHandler(c)
		return Render(c, 200, templates.FormattedYaml(b, err))
	})

	if err := e.Start(":1323"); err != nil {
		log.Logger.Error().Msgf("Error starting server: %v", err)
	}
}

// Only apply double quotes to string values, not keys
func quoteValuesOnly(n *yaml.Node) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			val := n.Content[i+1]

			// Apply recursively
			quoteValuesOnly(val)

			// Quote value if it's a string scalar
			if val.Kind == yaml.ScalarNode && val.Tag == "!!str" {
				val.Style = yaml.DoubleQuotedStyle
			}
			// Leave key unquoted
			if key.Kind == yaml.ScalarNode && key.Tag == "!!str" {
				key.Style = 0 // or yaml.TaggedStyle
			}
		}
	case yaml.SequenceNode, yaml.DocumentNode:
		for _, child := range n.Content {
			quoteValuesOnly(child)
		}
	}
}

func formatYAMLHandler(c echo.Context) ([]byte, error) {
	input := c.FormValue("yaml")

	// First, decode the YAML into a generic map
	var data interface{}
	if err := yaml.Unmarshal([]byte(input), &data); err != nil {
		return nil, err
	}

	// Then re-encode it with proper indentation
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	defer encoder.Close()

	if err := encoder.Encode(data); err != nil {
		return nil, err
	}

	// Now we need to read that back in to apply our quoting style
	var node yaml.Node
	if err := yaml.Unmarshal(buf.Bytes(), &node); err != nil {
		return nil, err
	}

	// Apply our quoting style
	quoteValuesOnly(&node)

	// Final encoding with proper quoting
	buf.Reset()
	encoder = yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	defer encoder.Close()

	if err := encoder.Encode(&node); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func Render(ctx echo.Context, statusCode int, t templ.Component) error {
	ctx.Response().WriteHeader(statusCode)
	ctx.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTML)
	return t.Render(ctx.Request().Context(), ctx.Response().Writer)
}

func ZerologMiddleware(logger zerolog.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			err := next(c)
			stop := time.Now()

			req := c.Request()
			res := c.Response()

			event := logger.Info().
				Str("method", req.Method).
				Str("uri", req.RequestURI).
				Int("status", res.Status).
				Dur("latency", stop.Sub(start)).
				Str("remote_ip", c.RealIP())

			if err != nil {
				c.Error(err)
				event.Err(err)
			}

			event.Msg("request handled")

			return err
		}
	}
}

func encrypt(c echo.Context) ([]byte, error) {

	ek := c.FormValue("encrypt-key")
	if ek == "" {
		return nil, fmt.Errorf("unable to extract [encrypt-key] FormValue")
	}

	ue, err := unencryptedTmp(c)
	if err != nil {
		return nil, fmt.Errorf("error creating unencrypted temp file: %v", err)
	}
	defer os.Remove(ue.Name())
	defer ue.Close()

	e, err := encryptedTmp()
	if err != nil {
		return nil, fmt.Errorf("error creating encrypted temp file %v", err)
	}
	defer os.Remove(e.Name())
	defer e.Close()

	// Java classpath and main class
	jarPath := "./static/secure-properties-tool.jar"
	mainClass := "com.mulesoft.tools.SecurePropertiesTool"

	// Command arguments
	args := []string{
		"-cp", jarPath,
		mainClass,
		"file", "encrypt", "Blowfish", "CBC",
		ek,
		ue.Name(), //unencrypted temp file
		e.Name(),  //encrypted temp file
	}

	cmd := exec.Command("java", args...)

	// Pipe output to terminal
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run the command
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error running SecurePropertiesTool: %v\n", err)
		os.Exit(1)
	}
	data, err := os.ReadFile(e.Name())
	if err != nil {
		return nil, fmt.Errorf("error reading encrypted.properties: %v", err)
	}
	return data, err
}

func encryptedTmp() (*os.File, error) {
	e, err := os.CreateTemp("./tmp", "encrypted-*.yaml")
	if err != nil {
		return nil, err
	}

	return e, nil
}

func unencryptedTmp(c echo.Context) (*os.File, error) {
	ue, err := os.CreateTemp("./tmp", "unencrypted-*.yaml")
	if err != nil {
		return nil, err
	}
	yaml := c.FormValue("yaml")
	if _, err := ue.WriteString(yaml); err != nil {
		return nil, err
	}

	return ue, err
}
