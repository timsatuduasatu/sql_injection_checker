<?php

namespace detect_sql_injection;

class TrieNode {
    public $children;
    public $isEndOfWord;

    public function __construct() {
        $this->children = array_fill(0, 256, null);
        $this->isEndOfWord = false;
    }
}

class SQLInjectionChecker {
    public $root;
    public $keywords;

    public function __construct() {
        $this->root = new TrieNode();
        $this->keywords = array();
    }

    public function addKeyword($keyword) {
        $node = $this->root;

        for ($i = 0; $i < strlen($keyword); $i++) {
            $index = ord($keyword[$i]);

            if ($node->children[$index] === null) {
                $node->children[$index] = new TrieNode();
            }

            $node = $node->children[$index];
        }

        $node->isEndOfWord = true;
    }

    public function addRegexKeyword($regexKeyword) {
        $this->keywords[] = $regexKeyword;
    }

    public function addRegexKeywordFromFile($filename) {
        $lines = file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        foreach ($lines as $line) {
            // Tidak perlu mengubah karakter pemisah
            $regexKeyword = $line;

            $this->addRegexKeyword($regexKeyword);
        }
    }

    private function buildAutomaton($keywords) {
        $root = new TrieNode();
        $queue = array();

        foreach ($keywords as $keyword) {
            $node = $root;
            $length = strlen($keyword);

            for ($i = 0; $i < $length; $i++) {
                $index = ord($keyword[$i]);

                if ($node->children[$index] === null) {
                    $node->children[$index] = new TrieNode();
                }

                $node = $node->children[$index];
            }

            $node->isEndOfWord = true;
            $queue[] = $node;
        }

        while (!empty($queue)) {
            $currentNode = array_shift($queue);

            for ($i = 0; $i < 256; $i++) {
                if ($currentNode->children[$i] !== null) {
                    $childNode = $currentNode->children[$i];
                    $failureNode = $currentNode;

                    while ($failureNode !== $root && $failureNode->children[$i] === null) {
                        $failureNode = $failureNode->failure;
                    }

                    if ($failureNode->children[$i] !== null && $failureNode->children[$i] !== $childNode) {
                        $childNode->failure = $failureNode->children[$i];
                    } else {
                        $childNode->failure = $root;
                    }

                    $queue[] = $childNode;
                }
            }
        }

        return $root;
    }

    private function searchKeywords($automaton, $text) {
        $node = $automaton;
        $length = strlen($text);
        $matches = array();

        for ($i = 0; $i < $length; $i++) {
            $index = ord($text[$i]);

            while ($node->children[$index] === null && $node !== $automaton) {
                $node = $node->failure;
            }

            if ($node->children[$index] !== null) {
                $node = $node->children[$index];
            }

            if ($node->isEndOfWord) {
                $matches[] = substr($text, $i - strlen($node) + 1, strlen($node));
            }
        }

        return $matches;
    }

    public function checkSQLInjection() {
        $inputs = $_POST;

        if (empty($inputs)) {
            $inputs = $_GET;
        }

        if (is_array($inputs)) {
            foreach ($inputs as $key => $input) {
                $this->checkSingleInput($key, $input);
            }
        } else {
            $this->checkSingleInput(null, $inputs);
        }
    }

    private function checkSingleInput($key, $input) {
        $regexPattern = "~\b(" . implode("|", $this->keywords) . ")\b~i";
        $automaton = $this->buildAutomaton($this->keywords);
        $matches = array();

        preg_match_all($regexPattern, $input, $matchesRegex);
        $matchesAC = $this->searchKeywords($automaton, $input);

        $matches = array_merge($matchesRegex[0], $matchesAC);

        if (!empty($matches)) {
            $errorMessage = "Detected SQL Injection:\n";
            foreach ($matches as $match) {
                $errorMessage .= "Input: " . htmlspecialchars($input, ENT_QUOTES) . "\n";
                $errorMessage .= "Match: " . htmlspecialchars($match, ENT_QUOTES) . "\n\n";
            }

            // Log the error message
            $this->logError($errorMessage);

            // Show the floating tab or popup tab
            $this->showFloatingTab($errorMessage);
        } else {
            echo "Input " . htmlspecialchars($input, ENT_QUOTES) . " is safe.<br>";
        }
    }

    private function logError($errorMessage) {
        // Implement your own logic to log the error message
        // For example, you can write the error message to a log file
        $logFile = 'error.log';
        file_put_contents($logFile, $errorMessage . "\n", FILE_APPEND);
    }

    private function showFloatingTab($errorMessage) {
        echo "<script>
            let floatingTab = document.createElement('div');
            floatingTab.style.position = 'fixed';
            floatingTab.style.bottom = '20px';
            floatingTab.style.right = '20px';
            floatingTab.style.padding = '10px';
            floatingTab.style.background = '#f00';
            floatingTab.style.color = '#fff';
            floatingTab.style.cursor = 'pointer';
            floatingTab.innerHTML = 'SQL Injection Detected!';
            document.body.appendChild(floatingTab);
            floatingTab.addEventListener('click', function() {
                let popupTab = window.open('', '_blank');
                popupTab.document.write('<html><head><title>SQL Injection Detected</title></head><body>');
                popupTab.document.write('<h1>SQL Injection Detected</h1>');
                popupTab.document.write('<p>' + " . json_encode(htmlspecialchars($errorMessage, ENT_QUOTES)) . " + '</p>');
                popupTab.document.write('<button onclick=\"window.close()\">Close</button>');
                popupTab.document.write('</body></html>');
            });
        </script>";
    }
}

$keywordsFile = 'sql_injection/payload.txt'; 

$checker = new SQLInjectionChecker();
$checker->addRegexKeywordFromFile($keywordsFile);

$checker->checkSQLInjection();
?>
