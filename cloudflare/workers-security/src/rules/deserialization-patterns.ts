/**
 * Insecure Deserialization Attack Patterns
 * Detection patterns for various serialization formats and attack vectors
 */

/**
 * Base64 encoded payload patterns
 * These patterns detect common base64-encoded serialization attack payloads
 */
export const BASE64_PATTERNS = {
  // Java serialization magic bytes (AC ED 00 05) in base64
  JAVA_SERIALIZATION: /rO0AB|sr\d{4}|yLnR5cGUu|b3Blbi9qYXZh/i,
  
  // .NET binary serialization patterns
  DOTNET_BINARY: /AAEAAAD\/\/\/\/\/|AAAAAAAAAAk|QklOQVJZU|TVNGVFRDRw/i,
  
  // Python pickle patterns
  PYTHON_PICKLE: /gASV|Y3Bvc2l4|gAJjcG9z|Y19fYnVpbHRpbl9f/i,
  
  // PHP serialization patterns
  PHP_SERIALIZATION: /Tzo0Oj|TzoxMD|YTo|czox|aTox/i,
  
  // Generic base64 detection for suspicious payloads
  SUSPICIOUS_BASE64: /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/,
};

/**
 * Java deserialization attack patterns
 * Common patterns found in Java deserialization exploits
 */
export const JAVA_PATTERNS = {
  // Magic bytes for Java serialized objects
  MAGIC_BYTES: /\xac\xed\x00\x05/,
  
  // Common gadget chain classes
  GADGET_CHAINS: [
    'org.apache.commons.collections.Transformer',
    'org.apache.commons.collections.functors.InvokerTransformer',
    'org.apache.commons.collections.functors.ChainedTransformer',
    'org.apache.commons.collections.functors.ConstantTransformer',
    'org.apache.commons.collections.keyvalue.TiedMapEntry',
    'org.apache.commons.beanutils.BeanComparator',
    'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
    'java.lang.Runtime',
    'java.lang.ProcessBuilder',
    'javax.management.BadAttributeValueExpException',
    'com.sun.rowset.JdbcRowSetImpl',
    'org.springframework.beans.factory.ObjectFactory',
    'org.codehaus.groovy.runtime.MethodClosure',
  ],
  
  // Dangerous method patterns
  DANGEROUS_METHODS: [
    'getRuntime',
    'exec(',
    'ProcessBuilder',
    'readObject',
    'writeObject',
    'invoke(',
    'forName(',
    'newInstance',
    'getMethod',
    'getDeclaredMethod',
  ],
};

/**
 * Python pickle deserialization patterns
 */
export const PYTHON_PATTERNS = {
  // Pickle opcodes that indicate code execution
  DANGEROUS_OPCODES: [
    '__reduce__',
    '__reduce_ex__',
    '__getstate__',
    '__setstate__',
    '__class__',
    '__bases__',
    '__subclasses__',
    '__mro__',
    '__globals__',
    '__builtins__',
  ],
  
  // Common payload patterns
  PAYLOAD_PATTERNS: [
    'os.system',
    'os.popen',
    'subprocess',
    'eval(',
    'exec(',
    'compile(',
    '__import__',
    'builtins',
    'posix.system',
  ],
};

/**
 * .NET deserialization patterns
 */
export const DOTNET_PATTERNS = {
  // Dangerous types in .NET
  DANGEROUS_TYPES: [
    'System.Windows.Data.ObjectDataProvider',
    'System.Diagnostics.Process',
    'System.Web.UI.ObjectStateFormatter',
    'System.Runtime.Serialization.Formatters.Binary.BinaryFormatter',
    'System.Activities.Presentation.WorkflowDesigner',
    'Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties',
    'System.Data.Services.Internal.ExpandedWrapper',
    'System.Security.Principal.WindowsPrincipal',
    'System.IdentityModel.Tokens.SessionSecurityToken',
    'System.Windows.ResourceDictionary',
  ],
  
  // .NET gadget patterns
  GADGET_PATTERNS: [
    'TypeConfuseDelegate',
    'ActivitySurrogateSelector',
    'PSObject',
    'ClaimsPrincipal',
  ],
};

/**
 * PHP deserialization patterns
 */
export const PHP_PATTERNS = {
  // PHP serialization format patterns
  SERIALIZED_OBJECT: /O:\d+:"[^"]+"/,
  SERIALIZED_ARRAY: /a:\d+:{/,
  
  // Dangerous PHP magic methods
  MAGIC_METHODS: [
    '__destruct',
    '__wakeup',
    '__toString',
    '__call',
    '__callStatic',
    '__get',
    '__set',
    '__isset',
    '__unset',
  ],
  
  // Common PHP gadget classes
  GADGET_CLASSES: [
    'Monolog\\Handler\\BufferHandler',
    'Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter',
    'Guzzle\\Http',
    'PHPUnit\\Framework\\MockObject\\MockObject',
    'Doctrine\\Common\\Cache\\',
    'Laravel\\',
  ],
};

/**
 * JSON deserialization patterns
 * While JSON itself is safe, certain frameworks can be exploited
 */
export const JSON_PATTERNS = {
  // Type hints that could indicate polymorphic deserialization
  TYPE_HINTS: [
    '@type',
    '$type',
    '__type',
    'class',
    'classname',
    '__class__',
    'javaClass',
    'targetClass',
  ],
  
  // Common JSON gadget patterns
  GADGET_PATTERNS: [
    'com.sun.org.apache.xalan',
    'org.apache.xbean',
    'com.mchange.v2.c3p0',
    'org.hibernate',
    'com.alibaba.fastjson',
    'net.sf.json',
    'org.json',
  ],
};

/**
 * XML deserialization patterns (XXE and XML-based deserialization)
 */
export const XML_PATTERNS = {
  // XXE patterns
  XXE_PATTERNS: [
    '<!ENTITY',
    '<!DOCTYPE',
    'SYSTEM "file:',
    'SYSTEM "http:',
    'PUBLIC "-//W3C',
    '<!ELEMENT',
    '<?xml version',
  ],
  
  // Dangerous XML elements for deserialization
  DANGEROUS_ELEMENTS: [
    '<java.',
    '<bean',
    '<object',
    '<script',
    '<invoke',
    '<set>',
    '<get>',
  ],
};

/**
 * YAML deserialization patterns
 */
export const YAML_PATTERNS = {
  // Dangerous YAML tags
  DANGEROUS_TAGS: [
    '!!python/',
    '!ruby/',
    '!java/',
    '!!python/object',
    '!!python/object/apply',
    '!!python/module',
  ],
  
  // Patterns that indicate code execution
  CODE_EXECUTION: [
    'subprocess.Popen',
    'os.system',
    'eval:',
    '!ruby/object:Gem',
  ],
};

/**
 * Combined deserialization detection patterns
 */
export interface DeserializationPattern {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  patterns: RegExp[];
  strings: string[];
}

/**
 * All deserialization attack patterns
 */
export const DESERIALIZATION_PATTERNS: DeserializationPattern[] = [
  {
    id: 'deser-java-001',
    name: 'Java Serialization Magic Bytes',
    description: 'Detects Java serialized object magic bytes (base64 encoded)',
    severity: 'critical',
    patterns: [BASE64_PATTERNS.JAVA_SERIALIZATION, /\xac\xed\x00\x05/],
    strings: ['rO0AB', 'sr00', 'aced0005'],
  },
  {
    id: 'deser-java-002',
    name: 'Java Gadget Chain Classes',
    description: 'Detects known Java deserialization gadget classes',
    severity: 'critical',
    patterns: [
      /org\.apache\.commons\.collections/i,
      /InvokerTransformer|ChainedTransformer|ConstantTransformer/i,
      /com\.sun\.org\.apache\.xalan/i,
      /TemplatesImpl/i,
    ],
    strings: JAVA_PATTERNS.GADGET_CHAINS,
  },
  {
    id: 'deser-python-001',
    name: 'Python Pickle Attack',
    description: 'Detects Python pickle deserialization attacks',
    severity: 'critical',
    patterns: [
      BASE64_PATTERNS.PYTHON_PICKLE,
      /__reduce__|__reduce_ex__/i,
    ],
    strings: PYTHON_PATTERNS.PAYLOAD_PATTERNS,
  },
  {
    id: 'deser-dotnet-001',
    name: '.NET Binary Formatter Attack',
    description: 'Detects .NET BinaryFormatter deserialization attacks',
    severity: 'critical',
    patterns: [
      BASE64_PATTERNS.DOTNET_BINARY,
      /ObjectDataProvider|ObjectStateFormatter/i,
    ],
    strings: DOTNET_PATTERNS.DANGEROUS_TYPES,
  },
  {
    id: 'deser-php-001',
    name: 'PHP Object Injection',
    description: 'Detects PHP object injection attacks',
    severity: 'high',
    patterns: [
      PHP_PATTERNS.SERIALIZED_OBJECT,
      BASE64_PATTERNS.PHP_SERIALIZATION,
    ],
    strings: PHP_PATTERNS.MAGIC_METHODS,
  },
  {
    id: 'deser-json-001',
    name: 'JSON Type Confusion',
    description: 'Detects JSON polymorphic deserialization attacks',
    severity: 'high',
    patterns: [
      /"@type"\s*:\s*"/i,
      /"\$type"\s*:\s*"/i,
      /"__type"\s*:\s*"/i,
    ],
    strings: JSON_PATTERNS.TYPE_HINTS,
  },
  {
    id: 'deser-yaml-001',
    name: 'YAML Code Execution',
    description: 'Detects YAML deserialization code execution attempts',
    severity: 'critical',
    patterns: [
      /!!python\/object/i,
      /!!python\/object\/apply/i,
      /!ruby\/object/i,
    ],
    strings: YAML_PATTERNS.DANGEROUS_TAGS,
  },
  {
    id: 'deser-xml-001',
    name: 'XML External Entity (XXE)',
    description: 'Detects XXE attacks through XML deserialization',
    severity: 'critical',
    patterns: [
      /<!ENTITY\s+\w+\s+SYSTEM/i,
      /<!DOCTYPE\s+\w+\s+\[\s*<!ENTITY/i,
    ],
    strings: XML_PATTERNS.XXE_PATTERNS,
  },
  {
    id: 'deser-base64-001',
    name: 'Suspicious Base64 Payload',
    description: 'Detects base64-encoded serialization payloads',
    severity: 'medium',
    patterns: [
      /[A-Za-z0-9+\/]{100,}={0,2}/,
    ],
    strings: [],
  },
];

/**
 * Check if content contains deserialization attack patterns
 */
export function checkDeserializationPatterns(
  content: string,
  options?: { checkBase64?: boolean }
): {
  detected: boolean;
  matches: Array<{
    pattern: DeserializationPattern;
    matchedString?: string;
    matchedPattern?: string;
  }>;
} {
  const matches: Array<{
    pattern: DeserializationPattern;
    matchedString?: string;
    matchedPattern?: string;
  }> = [];

  // Normalize content
  const normalizedContent = content.toLowerCase();
  
  // Optionally decode base64 for deeper inspection
  let decodedContent = '';
  if (options?.checkBase64) {
    try {
      // Try to find and decode base64 segments
      const base64Regex = /[A-Za-z0-9+\/]{40,}={0,2}/g;
      const base64Matches = content.match(base64Regex);
      if (base64Matches) {
        for (const b64 of base64Matches) {
          try {
            decodedContent += atob(b64);
          } catch {
            // Not valid base64, skip
          }
        }
      }
    } catch {
      // Decoding failed, continue with original content
    }
  }

  const contentToCheck = content + ' ' + decodedContent;

  for (const pattern of DESERIALIZATION_PATTERNS) {
    // Check regex patterns
    for (const regex of pattern.patterns) {
      if (regex.test(contentToCheck)) {
        matches.push({
          pattern,
          matchedPattern: regex.source,
        });
        break;
      }
    }

    // Check string patterns
    for (const str of pattern.strings) {
      if (contentToCheck.toLowerCase().includes(str.toLowerCase())) {
        matches.push({
          pattern,
          matchedString: str,
        });
        break;
      }
    }
  }

  // Remove duplicates
  const uniqueMatches = matches.filter(
    (match, index, self) =>
      index === self.findIndex((m) => m.pattern.id === match.pattern.id)
  );

  return {
    detected: uniqueMatches.length > 0,
    matches: uniqueMatches,
  };
}

/**
 * Get highest severity from matches
 */
export function getHighestSeverity(
  matches: Array<{ pattern: DeserializationPattern }>
): 'critical' | 'high' | 'medium' | 'low' | 'none' {
  if (matches.length === 0) return 'none';

  const severityOrder = ['critical', 'high', 'medium', 'low'];
  
  for (const severity of severityOrder) {
    if (matches.some((m) => m.pattern.severity === severity)) {
      return severity as 'critical' | 'high' | 'medium' | 'low';
    }
  }

  return 'none';
}

