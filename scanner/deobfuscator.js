// Deobfuscation engine for AgentShield
// Peels back layers of obfuscation to expose hidden malicious code

class Deobfuscator {
  constructor() {
    this.maxIterations = 10; // prevent infinite loops
    this.obfuscationDetected = false;
    this.obfuscationTypes = [];
    this.transformations = [];
  }

  /**
   * Main entry point: deobfuscate code and return both original + cleaned versions
   * @param {string} code - The original source code
   * @returns {{ original: string, deobfuscated: string, obfuscationDetected: boolean, obfuscationTypes: string[], transformations: string[] }}
   */
  deobfuscate(code) {
    this.obfuscationDetected = false;
    this.obfuscationTypes = [];
    this.transformations = [];

    let result = code;
    let previous = '';
    let iterations = 0;

    // Iteratively apply deobfuscation passes until stable
    while (result !== previous && iterations < this.maxIterations) {
      previous = result;
      result = this._applyAllPasses(result);
      iterations++;
    }

    return {
      original: code,
      deobfuscated: result,
      obfuscationDetected: this.obfuscationDetected,
      obfuscationTypes: [...new Set(this.obfuscationTypes)],
      transformations: this.transformations
    };
  }

  _applyAllPasses(code) {
    let result = code;
    result = this._decodeHexUnicodeEscapes(result);
    result = this._decodeUrlEncoding(result);
    result = this._resolveStringConcatenation(result);
    result = this._decodeBase64Strings(result);
    result = this._unwrapEvalFunction(result);
    result = this._resolveCharCodePatterns(result);
    result = this._resolveVariableAssignments(result);
    result = this._resolveTemplateLiterals(result);
    result = this._decodeRot13(result);
    result = this._resolveReverseStrings(result);
    result = this._resolveArrayAccessObfuscation(result);
    return result;
  }

  /**
   * 1. Decode base64 strings — Buffer.from('...','base64'), atob('...')
   */
  _decodeBase64Strings(code) {
    let result = code;

    // Buffer.from('...', 'base64').toString(...)
    result = result.replace(
      /Buffer\.from\(\s*['"]([A-Za-z0-9+\/=]+)['"]\s*,\s*['"]base64['"]\s*\)(?:\.toString\(\s*['"]?[^)]*['"]?\s*\))?/g,
      (match, b64) => {
        try {
          const decoded = Buffer.from(b64, 'base64').toString('utf8');
          // Only replace if it looks like valid text
          if (/^[\x20-\x7E\s]+$/.test(decoded) && decoded.length > 0) {
            this._flag('base64', `Buffer.from base64 → "${decoded.substring(0, 80)}"`);
            return `"${this._escapeString(decoded)}"`;
          }
        } catch (e) {}
        return match;
      }
    );

    // atob('...')
    result = result.replace(
      /atob\(\s*['"]([A-Za-z0-9+\/=]+)['"]\s*\)/g,
      (match, b64) => {
        try {
          const decoded = Buffer.from(b64, 'base64').toString('utf8');
          if (/^[\x20-\x7E\s]+$/.test(decoded) && decoded.length > 0) {
            this._flag('base64', `atob base64 → "${decoded.substring(0, 80)}"`);
            return `"${this._escapeString(decoded)}"`;
          }
        } catch (e) {}
        return match;
      }
    );

    // Standalone base64 strings in quotes that decode to URLs or commands
    result = result.replace(
      /(['"])([A-Za-z0-9+\/]{20,}={0,2})\1/g,
      (match, quote, b64) => {
        try {
          const decoded = Buffer.from(b64, 'base64').toString('utf8');
          // Only replace if decoded looks like a URL, path, or command
          if (/^[\x20-\x7E]+$/.test(decoded) && 
              (decoded.includes('http') || decoded.includes('/') || decoded.includes('eval') ||
               decoded.includes('exec') || decoded.includes('curl') || decoded.includes('wget'))) {
            this._flag('base64', `base64 string → "${decoded.substring(0, 80)}"`);
            return `${quote}${decoded}${quote}`;
          }
        } catch (e) {}
        return match;
      }
    );

    return result;
  }

  /**
   * 2. Resolve string concatenation — "h"+"t"+"t"+"p" → "http"
   */
  _resolveStringConcatenation(code) {
    let result = code;
    let changed = true;

    while (changed) {
      changed = false;
      // Match "str1" + "str2" (with both single and double quotes)
      const newResult = result.replace(
        /(['"])([^'"]*)\1\s*\+\s*(['"])([^'"]*)\3/g,
        (match, q1, s1, q2, s2) => {
          changed = true;
          this._flag('string-concatenation', `"${s1}" + "${s2}" → "${s1}${s2}"`);
          return `"${s1}${s2}"`;
        }
      );
      result = newResult;
    }

    return result;
  }

  /**
   * 3. Resolve hex (\x68) and unicode (\u0068) escape sequences
   */
  _decodeHexUnicodeEscapes(code) {
    let result = code;

    // Hex escapes: \x68\x74\x74\x70
    const hexPattern = /(?:\\x[0-9a-fA-F]{2}){2,}/g;
    result = result.replace(hexPattern, (match) => {
      try {
        const decoded = match.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        );
        if (/^[\x20-\x7E]+$/.test(decoded)) {
          this._flag('hex-escape', `hex escape → "${decoded.substring(0, 80)}"`);
          return decoded;
        }
      } catch (e) {}
      return match;
    });

    // Unicode escapes: \u0068\u0074\u0074\u0070
    const unicodePattern = /(?:\\u[0-9a-fA-F]{4}){2,}/g;
    result = result.replace(unicodePattern, (match) => {
      try {
        const decoded = match.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        );
        if (/^[\x20-\x7E]+$/.test(decoded)) {
          this._flag('unicode-escape', `unicode escape → "${decoded.substring(0, 80)}"`);
          return decoded;
        }
      } catch (e) {}
      return match;
    });

    // Hex escapes within string literals (handles quoted strings with \x sequences)
    result = result.replace(
      /(['"])((?:[^'"\\]|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[^xu])*)\1/g,
      (match, quote, inner) => {
        if (!/\\[xu]/.test(inner)) return match;
        try {
          let decoded = inner
            .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
            .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
          if (/^[\x20-\x7E\s]*$/.test(decoded)) {
            this._flag('hex-in-string', `escaped string → "${decoded.substring(0, 80)}"`);
            return `"${this._escapeString(decoded)}"`;
          }
        } catch (e) {}
        return match;
      }
    );

    return result;
  }

  /**
   * 4. Decode URL encoding — %68%74%74%70 → "http"
   */
  _decodeUrlEncoding(code) {
    let result = code;

    // URL encoded strings (at least 2 consecutive %XX sequences)
    result = result.replace(
      /(['"])((?:%[0-9a-fA-F]{2}){2,}[^'"]*)\1/g,
      (match, quote, encoded) => {
        try {
          const decoded = decodeURIComponent(encoded);
          if (decoded !== encoded) {
            this._flag('url-encoding', `URL encoded → "${decoded.substring(0, 80)}"`);
            return `${quote}${decoded}${quote}`;
          }
        } catch (e) {}
        return match;
      }
    );

    // decodeURIComponent / decodeURI calls with static strings
    result = result.replace(
      /(?:decodeURIComponent|decodeURI)\(\s*['"]([^'"]+)['"]\s*\)/g,
      (match, encoded) => {
        try {
          const decoded = decodeURIComponent(encoded);
          if (decoded !== encoded) {
            this._flag('url-encoding', `decodeURIComponent → "${decoded.substring(0, 80)}"`);
            return `"${this._escapeString(decoded)}"`;
          }
        } catch (e) {}
        return match;
      }
    );

    return result;
  }

  /**
   * 5. Unwrap eval() / Function() wrappers to expose inner code
   */
  _unwrapEvalFunction(code) {
    let result = code;

    // eval("...code...") — extract the string content
    result = result.replace(
      /eval\(\s*(['"])([\s\S]*?)\1\s*\)/g,
      (match, quote, inner) => {
        this._flag('eval-wrapper', `eval() unwrapped: "${inner.substring(0, 80)}..."`);
        return `/* EVAL_UNWRAPPED */ ${inner}`;
      }
    );

    // new Function("...code...")  or  Function("...code...")
    result = result.replace(
      /(?:new\s+)?Function\(\s*(['"])([\s\S]*?)\1\s*\)/g,
      (match, quote, inner) => {
        // Skip if it looks like a parameter definition (has comma-separated args)
        if (/^[a-zA-Z_$,\s]+$/.test(inner)) return match;
        this._flag('function-constructor', `Function() unwrapped: "${inner.substring(0, 80)}..."`);
        return `/* FUNCTION_UNWRAPPED */ ${inner}`;
      }
    );

    // eval(expr) where expr is a variable — flag but don't resolve
    result = result.replace(
      /eval\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\)/g,
      (match, varName) => {
        this._flag('eval-dynamic', `eval() with dynamic variable: ${varName}`);
        return `/* EVAL_DYNAMIC: ${varName} */ ${match}`;
      }
    );

    return result;
  }

  /**
   * 6. Resolve String.fromCharCode patterns
   */
  _resolveCharCodePatterns(code) {
    let result = code;

    // String.fromCharCode(104, 116, 116, 112)
    result = result.replace(
      /String\.fromCharCode\(\s*([\d,\s]+)\s*\)/g,
      (match, codes) => {
        try {
          const chars = codes.split(',').map(c => parseInt(c.trim(), 10));
          if (chars.some(isNaN)) return match;
          const decoded = String.fromCharCode(...chars);
          if (/^[\x20-\x7E\s]+$/.test(decoded)) {
            this._flag('charcode', `String.fromCharCode → "${decoded.substring(0, 80)}"`);
            return `"${this._escapeString(decoded)}"`;
          }
        } catch (e) {}
        return match;
      }
    );

    // [104,116,116,112].map(c => String.fromCharCode(c)).join('')
    result = result.replace(
      /\[\s*([\d,\s]+)\s*\]\s*\.map\(\s*(?:function\s*\(\s*\w+\s*\)\s*\{\s*return\s+String\.fromCharCode\(\s*\w+\s*\)\s*;?\s*\}|(?:\w+|\(\s*\w+\s*\))\s*=>\s*String\.fromCharCode\(\s*\w+\s*\))\s*\)\s*\.join\(\s*['"]?['"]\s*\)/g,
      (match, codes) => {
        try {
          const chars = codes.split(',').map(c => parseInt(c.trim(), 10));
          if (chars.some(isNaN)) return match;
          const decoded = String.fromCharCode(...chars);
          if (/^[\x20-\x7E\s]+$/.test(decoded)) {
            this._flag('charcode-array', `charCode array → "${decoded.substring(0, 80)}"`);
            return `"${this._escapeString(decoded)}"`;
          }
        } catch (e) {}
        return match;
      }
    );

    return result;
  }

  /**
   * 7. Resolve variable assignments that build strings incrementally
   *    var a = "ht"; a += "tp"; a += "://evil.com"
   */
  _resolveVariableAssignments(code) {
    let result = code;
    const varMap = new Map();

    // First pass: find var/let/const assignments to string literals
    const initPattern = /(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(['"])([^'"]*)\2\s*;?/g;
    let match;
    while ((match = initPattern.exec(code)) !== null) {
      varMap.set(match[1], match[3]);
    }

    // Second pass: find += string concatenations
    const concatPattern = /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\+=\s*(['"])([^'"]*)\2\s*;?/g;
    while ((match = concatPattern.exec(code)) !== null) {
      const varName = match[1];
      if (varMap.has(varName)) {
        varMap.set(varName, varMap.get(varName) + match[3]);
      }
    }

    // Check if any built-up strings look suspicious
    for (const [varName, value] of varMap) {
      if (value.length > 5 && (
        value.includes('http') || value.includes('eval') ||
        value.includes('exec') || value.includes('curl') ||
        value.includes('wget') || value.includes('.env') ||
        value.includes('process.') || value.includes('require')
      )) {
        this._flag('incremental-string', `Variable "${varName}" builds: "${value.substring(0, 100)}"`);
        // Add a comment revealing the resolved value
        result += `\n/* DEOBFUSCATED_VAR: ${varName} = "${this._escapeString(value)}" */`;
      }
    }

    return result;
  }

  /**
   * 8. Handle template literal obfuscation
   *    `${'h'}${'t'}${'t'}${'p'}` or tagged templates
   */
  _resolveTemplateLiterals(code) {
    let result = code;

    // Template literals with only ${'x'} interpolations
    // `${'h'}${'t'}${'t'}${'p'}`
    result = result.replace(
      /`((?:\$\{['"][^'"]*['"]\})+)`/g,
      (match, inner) => {
        const parts = [];
        const partPattern = /\$\{['"]([^'"]*)['"]\}/g;
        let partMatch;
        while ((partMatch = partPattern.exec(inner)) !== null) {
          parts.push(partMatch[1]);
        }
        const resolved = parts.join('');
        if (resolved.length > 0) {
          this._flag('template-literal', `template literal → "${resolved.substring(0, 80)}"`);
          return `"${this._escapeString(resolved)}"`;
        }
        return match;
      }
    );

    // Template with mixed static + single-char interpolations
    result = result.replace(
      /`([^`]*\$\{['"][^'"]{1,3}['"]\}[^`]*)`/g,
      (match, inner) => {
        // Only process if it has multiple interpolations
        const interpCount = (inner.match(/\$\{/g) || []).length;
        if (interpCount < 3) return match;

        let resolved = inner.replace(/\$\{['"]([^'"]*)['"]\}/g, '$1');
        if (resolved !== inner) {
          this._flag('template-literal', `template → "${resolved.substring(0, 80)}"`);
          return `"${this._escapeString(resolved)}"`;
        }
        return match;
      }
    );

    return result;
  }

  /**
   * 9. Decode ROT13 patterns
   */
  _decodeRot13(code) {
    let result = code;

    // .replace(/[a-zA-Z]/g, function(c) { ... charCodeAt ... 13 ... }) pattern near a string
    // This is a heuristic — flag the pattern as suspicious
    if (/\.replace\(\s*\/\[a-zA-Z\]\/g?\s*,\s*function\s*\(\s*\w+\s*\).*?13/s.test(code)) {
      this._flag('rot13', 'ROT13 encoding pattern detected');
    }

    return result;
  }

  /**
   * 10. Resolve reversed strings — "moc.live".split('').reverse().join('')
   */
  _resolveReverseStrings(code) {
    let result = code;

    result = result.replace(
      /(['"])([^'"]+)\1\s*\.split\(\s*['"]{2}\s*\)\s*\.reverse\(\s*\)\s*\.join\(\s*['"]{2}\s*\)/g,
      (match, quote, str) => {
        const reversed = str.split('').reverse().join('');
        this._flag('string-reverse', `reversed string → "${reversed.substring(0, 80)}"`);
        return `"${this._escapeString(reversed)}"`;
      }
    );

    return result;
  }

  /**
   * 11. Resolve array-based obfuscation
   *     var _0x = ["http","://","evil",".com"]; _0x[0]+_0x[1]+_0x[2]+_0x[3]
   */
  _resolveArrayAccessObfuscation(code) {
    let result = code;

    // Find array declarations: var _0xABC = ["str1", "str2", ...]
    const arrayPattern = /(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\[\s*((?:['"][^'"]*['"](?:\s*,\s*)?)+)\s*\]/g;
    let match;
    const arrays = new Map();

    while ((match = arrayPattern.exec(code)) !== null) {
      const varName = match[1];
      const elements = [];
      const elemPattern = /['"]([^'"]*)['"]/g;
      let elemMatch;
      while ((elemMatch = elemPattern.exec(match[2])) !== null) {
        elements.push(elemMatch[1]);
      }
      if (elements.length >= 2) {
        arrays.set(varName, elements);
      }
    }

    // Replace array[index] access with resolved values
    for (const [varName, elements] of arrays) {
      const accessPattern = new RegExp(
        varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\[\\s*(\\d+)\\s*\\]',
        'g'
      );
      const newResult = result.replace(accessPattern, (m, idx) => {
        const index = parseInt(idx, 10);
        if (index >= 0 && index < elements.length) {
          this._flag('array-access', `${varName}[${index}] → "${elements[index]}"`);
          return `"${this._escapeString(elements[index])}"`;
        }
        return m;
      });
      if (newResult !== result) {
        result = newResult;
      }
    }

    return result;
  }

  // --- Helpers ---

  _flag(type, detail) {
    this.obfuscationDetected = true;
    if (!this.obfuscationTypes.includes(type)) {
      this.obfuscationTypes.push(type);
    }
    this.transformations.push(detail);
  }

  _escapeString(str) {
    return str
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
  }
}

module.exports = { Deobfuscator };
