"""Streamlit configuration management interface with mTLS authentication."""

import streamlit as st
import logging
from pathlib import Path
from datetime import datetime
import json
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from config_service.config_manager import ConfigManager
from config_service.auth import MTLSAuthenticator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration paths
CONFIG_DIR = Path.home() / ".aceiot" / "config"
CA_DIR = Path.home() / ".aceiot" / "pki" / "ca"

# Initialize managers
config_manager = ConfigManager(CONFIG_DIR)

# Page configuration
st.set_page_config(
    page_title="AceIoT Configuration Manager",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)


def init_session_state():
    """Initialize session state variables."""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    if 'current_config' not in st.session_state:
        st.session_state.current_config = config_manager.load_config() or {}


def render_authentication():
    """Render authentication status."""
    st.sidebar.title("🔐 Authentication")

    if st.session_state.authenticated:
        st.sidebar.success("✅ Authenticated")
        if st.session_state.user_info:
            st.sidebar.write(f"**User:** {st.session_state.user_info.get('common_name', 'Unknown')}")
            st.sidebar.write(f"**Organization:** {st.session_state.user_info.get('organization', 'Unknown')}")
    else:
        st.sidebar.warning("⚠️ Not Authenticated")
        st.sidebar.info("""
        In production, mTLS authentication would be required.
        For development, using mock authentication.
        """)

        if st.sidebar.button("Simulate Authentication"):
            st.session_state.authenticated = True
            st.session_state.user_info = {
                'common_name': 'Developer',
                'organization': 'AceIoT'
            }
            st.rerun()


def render_config_editor():
    """Render configuration editor."""
    st.header("📝 Configuration Editor")

    # Load current config
    current_config = st.session_state.current_config

    # JSON editor
    col1, col2 = st.columns([3, 1])

    with col1:
        st.subheader("Current Configuration")

        # Convert to pretty JSON string
        config_str = json.dumps(current_config, indent=2)

        # Text area for editing
        edited_config = st.text_area(
            "Edit Configuration (JSON)",
            value=config_str,
            height=400,
            key="config_editor"
        )

    with col2:
        st.subheader("Actions")

        # Save button
        if st.button("💾 Save Configuration", use_container_width=True):
            try:
                # Parse JSON
                new_config = json.loads(edited_config)

                # Get metadata
                author = st.session_state.user_info.get('common_name', 'unknown')
                comment = st.text_input("Change Description", key="save_comment")

                if comment:
                    # Save configuration
                    version = config_manager.save_config(
                        new_config,
                        author=author,
                        comment=comment
                    )

                    st.session_state.current_config = new_config
                    st.success(f"✅ Configuration saved as version {version}")
                    st.rerun()
                else:
                    st.warning("Please provide a change description")

            except json.JSONDecodeError as e:
                st.error(f"❌ Invalid JSON: {e}")
            except Exception as e:
                st.error(f"❌ Save failed: {e}")
                logger.error(f"Save failed: {e}")

        # Reload button
        if st.button("🔄 Reload", use_container_width=True):
            st.session_state.current_config = config_manager.load_config() or {}
            st.rerun()

        # Export button
        if st.button("📤 Export", use_container_width=True):
            try:
                export_data = config_manager.export_config()
                st.download_button(
                    label="Download Export",
                    data=json.dumps(export_data, indent=2),
                    file_name=f"config_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            except Exception as e:
                st.error(f"❌ Export failed: {e}")


def render_version_history():
    """Render version history."""
    st.header("📜 Version History")

    versions = config_manager.list_versions()

    if not versions:
        st.info("No version history available")
        return

    # Create table
    for version in versions:
        with st.expander(
            f"Version {version['version']} - {version['timestamp']} by {version['author']}"
        ):
            st.write(f"**Comment:** {version['comment']}")
            st.write(f"**Hash:** `{version['hash'][:16]}...`")

            col1, col2, col3 = st.columns(3)

            with col1:
                if st.button(f"👁️ View", key=f"view_{version['version']}"):
                    version_obj = config_manager.get_version(version['version'])
                    if version_obj:
                        st.json(version_obj.data)

            with col2:
                if st.button(f"↩️ Rollback", key=f"rollback_{version['version']}"):
                    author = st.session_state.user_info.get('common_name', 'unknown')
                    if config_manager.rollback(version['version'], author=author):
                        st.success(f"✅ Rolled back to version {version['version']}")
                        st.session_state.current_config = config_manager.load_config() or {}
                        st.rerun()
                    else:
                        st.error("❌ Rollback failed")

            with col3:
                if st.button(f"📊 Compare", key=f"compare_{version['version']}"):
                    st.session_state.compare_version = version['version']


def render_audit_log():
    """Render audit log."""
    st.header("📋 Audit Log")

    limit = st.slider("Number of entries", 10, 100, 50)
    entries = config_manager.get_audit_log(limit=limit)

    if not entries:
        st.info("No audit log entries")
        return

    # Display as table
    import pandas as pd

    df = pd.DataFrame(entries)
    st.dataframe(df, use_container_width=True)


def render_certificate_info():
    """Render certificate information."""
    st.sidebar.subheader("🔐 Certificate Info")

    root_ca_path = CA_DIR / "root_ca" / "root_ca.crt"

    if root_ca_path.exists():
        st.sidebar.success("Root CA: ✅ Available")

        # Show download button
        with open(root_ca_path, 'rb') as f:
            st.sidebar.download_button(
                label="📥 Download Root CA",
                data=f.read(),
                file_name="root_ca.crt",
                mime="application/x-pem-file"
            )
    else:
        st.sidebar.warning("Root CA: ⚠️ Not initialized")

    # List intermediate CAs
    intermediate_ca_path = CA_DIR / "intermediate_cas"
    if intermediate_ca_path.exists():
        server_ids = [
            p.name for p in intermediate_ca_path.iterdir()
            if p.is_dir() and (p / "intermediate_ca.crt").exists()
        ]

        if server_ids:
            st.sidebar.write(f"**Intermediate CAs:** {len(server_ids)}")
            for server_id in server_ids:
                st.sidebar.write(f"- {server_id}")
        else:
            st.sidebar.write("**Intermediate CAs:** 0")


def main():
    """Main application."""
    init_session_state()

    # Header
    st.title("🔐 AceIoT Configuration Manager")
    st.markdown("---")

    # Sidebar
    render_authentication()
    render_certificate_info()

    # Main content
    if not st.session_state.authenticated:
        st.warning("⚠️ Please authenticate to access configuration")
        st.info("""
        This interface requires mTLS authentication with a valid client certificate.

        **In production:**
        - Present client certificate from your server's intermediate CA
        - Certificate will be verified against the root CA chain
        - Only authenticated users can modify configuration

        **For development:**
        - Click "Simulate Authentication" in the sidebar
        """)
        return

    # Tabs
    tab1, tab2, tab3 = st.tabs(["📝 Editor", "📜 History", "📋 Audit Log"])

    with tab1:
        render_config_editor()

    with tab2:
        render_version_history()

    with tab3:
        render_audit_log()


if __name__ == "__main__":
    main()
