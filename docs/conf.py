# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
project = 'zephyr-snmp'
copyright = '2026, StructCore Embedded'
author = 'StructCore Embedded'
release = '1.0.0'

# -- General configuration ---------------------------------------------------
extensions = ['sphinx.ext.intersphinx', 'breathe']

# Breathe configuration
breathe_projects = {
    "zephyr-snmp": "_build_doxygen/xml"
}
breathe_default_project = "zephyr-snmp"

templates_path = ['_templates']
exclude_patterns = ['_build_sphinx', '_build_doxygen', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
try:
    import sphinx_rtd_theme
    html_theme = 'sphinx_rtd_theme'
except ImportError:
    html_theme = 'alabaster'

# -- Options for Intersphinx -------------------------------------------------
intersphinx_mapping = {
    'zephyr': ('https://docs.zephyrproject.org/latest/', None)
}
