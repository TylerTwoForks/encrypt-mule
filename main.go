package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"ttwoforks.com/encrypt/web/templates"
)

var logger zerolog.Logger

// Build info, injected at release time via -ldflags -X.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

//go:embed static/secure-properties-tool.jar
var securePropertiesJar []byte

// jarPath is the on-disk location of the embedded jar, resolved at startup.
var jarPath string

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("encrypt %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	p, err := extractJar()
	if err != nil {
		log.Logger.Fatal().Msgf("error extracting embedded jar: %v", err)
	}
	jarPath = p

	e := echo.New()
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	e.Use(ZerologMiddleware(logger))

	e.GET("/", func(c echo.Context) error {
		return Render(c, 200, templates.MainTempl())
	})

	e.POST("/", convert)

	e.POST("/format-yaml", func(c echo.Context) error {
		b, err := formatYAMLHandler(c)
		if err != nil {
			return Render(c, 200, templates.ConvertError(err))
		}
		return Render(c, 200, templates.TopTextarea(string(b)))
	})

	// Open the app in the user's default browser shortly after the server
	// comes up, so double-clicking the binary lands them on the UI.
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser("http://localhost:1323")
	}()

	if err := e.Start(":1323"); err != nil {
		log.Logger.Error().Msgf("Error starting server: %v", err)
	}
}

// extractJar writes the embedded SecurePropertiesTool jar to a stable temp
// location and returns its path, so the binary is self-contained.
func extractJar() (string, error) {
	dir := filepath.Join(os.TempDir(), "encrypt-mule")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "secure-properties-tool.jar")
	if err := os.WriteFile(p, securePropertiesJar, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// openBrowser opens url in the user's default browser. Best-effort: errors are
// ignored so a headless/server run still works.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux, etc.
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
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

// convert picks the direction based on which box has content: text in the top
// (plaintext) box encrypts into the bottom box; text in only the bottom
// (ciphertext) box decrypts into the top box. The top box wins if both are
// filled. htmx's HX-Retarget header steers the result to the opposite box.
func convert(c echo.Context) error {
	top := c.FormValue("yaml")
	bottom := c.FormValue("encrypted")

	switch {
	case strings.TrimSpace(top) != "":
		out, err := runTool(c, "encrypt", top)
		if err != nil {
			log.Logger.Error().Msgf("error encrypting: %v", err)
			return Render(c, http.StatusOK, templates.ConvertError(err))
		}
		c.Response().Header().Set("HX-Retarget", "#yaml-target")
		return Render(c, http.StatusOK, templates.BottomTextarea(string(out)))

	case strings.TrimSpace(bottom) != "":
		out, err := runTool(c, "decrypt", bottom)
		if err != nil {
			log.Logger.Error().Msgf("error decrypting: %v", err)
			return Render(c, http.StatusOK, templates.ConvertError(err))
		}
		c.Response().Header().Set("HX-Retarget", "#yaml")
		return Render(c, http.StatusOK, templates.TopTextarea(string(out)))

	default:
		return Render(c, http.StatusOK, templates.ConvertError(
			fmt.Errorf("enter YAML in the top box to encrypt, or the bottom box to decrypt")))
	}
}

// runTool shells out to the Mule SecurePropertiesTool to encrypt or decrypt the
// given input and returns the result. op is "encrypt" or "decrypt".
func runTool(c echo.Context, op, input string) ([]byte, error) {
	key := c.FormValue("encrypt-key")
	if key == "" {
		return nil, fmt.Errorf("unable to extract [encrypt-key] FormValue")
	}

	in, err := tmpFile(input)
	if err != nil {
		return nil, fmt.Errorf("error creating input temp file: %v", err)
	}
	defer os.Remove(in.Name())
	defer in.Close()

	out, err := tmpFile("")
	if err != nil {
		return nil, fmt.Errorf("error creating output temp file: %v", err)
	}
	defer os.Remove(out.Name())
	defer out.Close()

	mainClass := "com.mulesoft.tools.SecurePropertiesTool"

	args := []string{
		"-cp", jarPath,
		mainClass,
		"file", op, "Blowfish", "CBC",
		key,
		in.Name(),  // input temp file
		out.Name(), // output temp file
	}

	cmd := exec.Command("java", args...)

	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error running SecurePropertiesTool (%s): %v: %s", op, err, stderr.String())
	}

	data, err := os.ReadFile(out.Name())
	if err != nil {
		return nil, fmt.Errorf("error reading %s output: %v", op, err)
	}
	return data, nil
}

// tmpFile creates a temp file in the OS temp dir, writing contents if non-empty.
func tmpFile(contents string) (*os.File, error) {
	f, err := os.CreateTemp("", "convert-*.yaml")
	if err != nil {
		return nil, err
	}
	if contents != "" {
		if _, err := f.WriteString(contents); err != nil {
			f.Close()
			os.Remove(f.Name())
			return nil, err
		}
	}
	return f, nil
}
