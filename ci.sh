#!/bin/bash
############################################################
# Script to perform the "Continuous Integration" validation
############################################################
# Create VENV
python -m venv pyenv
source pyenv/bin/activate
# Install the validation tool
pip install skills-ref
# Validate all skills
skills_base_folder=".claude/skills"
for skill_folder in $(ls $skills_base_folder)
do
    skill_file="$skills_base_folder/$skill_folder/SKILL.md"
    echo "[+] Validate skill file: $skill_file" 
    pyenv/bin/agentskills validate $skill_file
done
echo "[+] Scan the skills with NVIDIA/SkillSpector"
cd .claude
zip -r /tmp/skills.zip skills/ 
cd ..
file /tmp/skills.zip
unzip -l /tmp/skills.zip
git clone --depth 1 https://github.com/NVIDIA/SkillSpector.git /tmp/skillspector
docker build -t skillspector /tmp/skillspector
risk_assessment_recommendation=$(docker run --rm -v "/tmp:/scan" skillspector scan /scan/skills.zip --no-llm --format json | jq -r '.risk_assessment.recommendation')
rm -rf /tmp/skillspector
if [ "$risk_assessment_recommendation" != "SAFE" ]
then
  echo "[!] SkillSpector identified the skills has not safe: $risk_assessment_recommendation"
  docker run --rm -v "/tmp:/scan" skillspector scan /scan/skills.zip --no-llm
  exit 1
else
  echo "[V] SkillSpector identified the skills has safe!"
  exit 0
fi