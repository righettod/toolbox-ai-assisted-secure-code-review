# Convert Claude Skills to Vibe CLI Skills

## Objective

Convert all skills from the `.claude/skills/` directory into Vibe CLI-compatible skills that can be used in this environment.

## Skills to Convert

All skills contained in the `.claude/skills/` directory, regardless of quantity or type. The conversion process is designed to handle any number of skills dynamically, including:

- Main skills with their own SKILL.md files
- Skills with sub-skills (like codebase-hotspotsv2 with its agent subdirectories)
- Any future skills that may be added to the directory

The process will automatically discover and convert all skills present in the source directory.

## Conversion Requirements

For each skill, create a Vibe CLI-compatible skill by:

1. **Creating a SKILL.md file** in the appropriate Vibe skills directory structure
2. **Adapting the frontmatter** to Vibe CLI format:
   - **Add or keep the `name` field**: Use the skill directory name as the value. This field is required by Vibe CLI but may be missing from original Claude skills.
   - Keep the `description` field
   - Remove `argument-hint` (Vibe uses different argument handling)
   - Map `allowed-tools` to Vibe's tool permissions
   - Remove `disable-model-invocation` (not applicable to Vibe)

3. **Adapting the skill content**:
   - Keep the core functionality and methodology
   - Replace Claude-specific tool references with Vibe equivalents
   - Update any path references to work in the Vibe environment
   - Maintain the same output format and structure

4. **Tool Mapping**:
   - `Read` → `read_file`
   - `Glob` → `bash` with `find` or equivalent
   - `Grep` → `grep`
   - `Bash` → `bash`
   - `TaskCreate` → `task` (for subagents)
   - `Write` → `write_file`

## Specific Conversion Notes

### For skills with sub-skills

Some skills (like codebase-hotspotsv2) have complex structures with dedicated agent sub-skills. Each sub-skill in subdirectories should be converted as separate skills that can be invoked by the main orchestrator skill.

### For visualization skills

Skills that generate visual outputs (like Mermaid flowcharts) should maintain their original output format, as Vibe CLI supports markdown and other visualization formats.

### For file parsing skills

Skills that parse external files (like Semgrep SARIF/JSON output) should adapt their file reading logic to use Vibe CLI's file reading tools.

### General approach

The conversion should preserve:

- Core functionality and methodology
- Output formats and structure
- Security analysis logic
- Tool usage patterns (adapted to Vibe CLI equivalents)

## Output Structure

Create the converted skills in `.vibe/skills/` within the current directory. The exact structure will mirror the source `.claude/skills/` directory:

```
.vibe/skills/
├── <skill1>/
│   └── SKILL.md
├── <skill2>/
│   ├── SKILL.md
│   ├── <sub-skill1>/
│   │   └── SKILL.md
│   ├── <sub-skill2>/
│   │   └── SKILL.md
│   └── ...
├── <skill3>/
│   └── SKILL.md
└── ...
```

The conversion process will:

- Preserve the original directory hierarchy from `.claude/skills/`
- Convert all SKILL.md files found in the directory tree
- Maintain any sub-skill relationships (like agent directories)
- Create skills in the standard `.vibe/skills/` location for automatic Vibe CLI discovery

## Implementation Steps

1. Create the `.vibe/skills/` directory in the current working directory
2. Discover all skills in `.claude/skills/` directory:
   - For each main skill directory found:
     - Create corresponding directory structure in `.vibe/skills/`
     - Convert the main SKILL.md file with appropriate adaptations
     - Recursively process any sub-skill directories (like agent subdirectories)
3. For each SKILL.md file found:
   - Apply tool reference mappings (Read→read_file, etc.)
   - Update path references to point to `.vibe/skills/`
   - Preserve all original functionality and output formats
   - Convert line endings from CRLF to LF using `dos2unix` or equivalent
   - Replace problematic UTF-8 characters with ASCII equivalents
   - Quote description fields containing colons to prevent YAML parsing errors
4. Test that all converted skills can be discovered and loaded by Vibe CLI

## Verification

After conversion, verify that:

- All skills are properly formatted for Vibe CLI
- Tool references are correctly mapped
- Path references are updated
- The skill hierarchy is preserved
- Output formats remain compatible
- Skills appear in Vibe CLI autocomplete (`vibe skills list`)
- Skills can be invoked successfully (`vibe skill <skill-name>`)
- No files is missing for every converted skills.

## Character Encoding and YAML Requirements

### Character Encoding Handling

1. **Line Endings:** Convert all files from CRLF (Windows) to LF (Unix) line endings using `dos2unix` or equivalent tool.

2. **UTF-8 Character Replacement:** Replace problematic UTF-8 characters with ASCII equivalents:
   - Em dash (`—`) → double hyphen (`--`)
   - Rightwards arrow (`→`) → hyphen+greater-than (`->`)
   - Leftwards arrow (`←`) → double hyphen (`--`)
   - Horizontal ellipsis (`…`) → three periods (`...`)
   - Smart quotes (`“”‘’`) → straight quotes (`""''`)
   - Subscript numbers (`₁₂₃`) → regular numbers (`123`)

### YAML Frontmatter Requirements

3. **Description Field Quoting:** If the `description` field contains colons (`:`), it must be quoted to prevent YAML parsing errors:
   ```yaml
   # Correct format for descriptions with colons
   description: "Text containing colons: like this example"
   ```

4. **Name Field Requirement:** Every skill must have a `name` field in the frontmatter that matches the directory name:
   ```yaml
   name: skill-directory-name
   ```

5. **Tool Reference Validation:** Ensure all tools referenced in `allowed-tools` are valid Vibe CLI tools and properly mapped from Claude equivalents.

### Path Reference Updates

6. **Remove Claude Path References:** Replace all references to `.claude/skills/` paths with generic descriptions or remove them entirely.

7. **Shared Rules Handling:** For skills referencing shared rules files, update to use generic descriptions like "shared security rules" instead of specific file paths.

### Validation Steps

8. **YAML Validation:** After conversion, validate each SKILL.md file's frontmatter using:
   ```bash
   python -c "import yaml; content = open('SKILL.md').read(); parts = content.split('---'); yaml.safe_load(parts[1])"
   ```

9. **Comprehensive Testing:** Test all converted skills to ensure they can be discovered and loaded by Vibe CLI.
