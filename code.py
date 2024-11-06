name: Run F5 Info Script

on:
  workflow_dispatch:

jobs:
  run-script:
    runs-on: self-hosted
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v3
        with:
          persist-credentials: false  # Important for using custom auth

      - name: Set up Git
        run: |
          git config --global user.name 'GitHub Actions Bot'
          git config --global user.email 'actions@github.com'

      - name: Install Dependencies
        run: |
          pip install requests urllib3

      - name: Run F5 Info Script
        env:
          BIGIP_USERNAME: ${{ secrets.BIGIP_USERNAME }}
          BIGIP_PASSWORD: ${{ secrets.BIGIP_PASSWORD }}
        run: |
          python f5_info_script.py

      - name: Commit and Push Changes
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          git pull origin ${GITHUB_REF#refs/heads/} --rebase
          git add README.md device_*.md virtual_servers_*.csv pool_members_*.csv problematic_virtual_servers.csv
          git commit -m "Update F5 reports [skip ci]" || echo "No changes to commit"
          git push https://${GITHUB_ACTOR}:${{ secrets.GITHUB_TOKEN }}@github.com/${{ github.repository }} HEAD:${GITHUB_REF#refs/heads/}
