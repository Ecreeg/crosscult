import streamlit as st
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
import requests
import json

# --- PAGE CONFIG ---
st.set_page_config(page_title="🌍 Cross-Culture Humor Translator", page_icon="😂")

st.title("🌏 Cross-Culture Humor & Language Mapper")
st.write("Translate humor across cultures with AI and a touch of fun! ✨")

# --- AUTHENTICATION SECTION ---
def show_login():
    st.subheader("🔐 Login with Google")

    # Google OAuth URL setup
    google_client_id = st.secrets["GOOGLE_CLIENT_ID"]
    redirect_uri = "https://crossculture.streamlit.app/"
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={google_client_id}&"
        "response_type=token&"
        f"redirect_uri={redirect_uri}&"
        "scope=email%20profile"
    )

    # Button to start login
    st.markdown(f"[Login with Google]({auth_url})", unsafe_allow_html=True)
    st.info("Once logged in, Google will redirect you back to this page.")

# --- MAIN APP ---
def show_main_app(user_email):
    st.success(f"👋 Welcome, {user_email}!")

    st.header("😂 Cross-Culture Joke Translator")

    source_culture = st.selectbox("🎭 Source Culture", ["American", "British", "Indian", "Japanese", "Other"])
    target_culture = st.selectbox("🎯 Target Culture", ["Indian", "American", "British", "Japanese", "Other"])
    target_language = st.selectbox("🗣️ Target Language", ["English", "Hindi", "Tamil", "Spanish", "French", "German", "Japanese"])
    joke = st.text_area("💬 Enter your joke", placeholder="Type your joke here...")

    if st.button("🪄 Translate"):
        if not joke:
            st.warning("Please enter a joke first!")
        else:
            with st.spinner("Translating..."):
                try:
                    headers = {
                        "Authorization": f"Bearer {st.secrets['OPENROUTER_API_KEY']}",
                        "Content-Type": "application/json"
                    }

                    prompt = (
                        f"Translate this joke from {source_culture} culture to {target_culture} culture "
                        f"in {target_language}. Preserve the humor but adapt to cultural context.\n\nJoke: {joke}"
                    )

                    data = {
                        "model": "mistralai/mistral-small-3.2-24b-instruct:free",
                        "messages": [
                            {"role": "system", "content": "You are a multilingual humor translator."},
                            {"role": "user", "content": prompt}
                        ]
                    }

                    response = requests.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        headers=headers,
                        data=json.dumps(data)
                    )

                    if response.status_code == 200:
                        result = response.json()
                        output = result["choices"][0]["message"]["content"]
                        st.markdown(f"### ✅ Translated Joke in {target_language}:")
                        st.markdown(output)
                    else:
                        st.error(f"Error: {response.status_code}\n{response.text}")

                except Exception as e:
                    st.error(f"Unexpected error: {e}")

    if st.button("🚪 Logout"):
        st.session_state["user_email"] = None
        st.experimental_rerun()

# --- AUTH LOGIC ---
if "user_email" not in st.session_state:
    # Detect token from URL hash (if logged in)
    query_params = st.query_params
    if "access_token" in query_params:
        access_token = query_params["access_token"]
        try:
            idinfo = id_token.verify_oauth2_token(access_token, grequests.Request(), st.secrets["GOOGLE_CLIENT_ID"])
            st.session_state["user_email"] = idinfo["email"]
        except Exception:
            st.warning("Login failed. Please try again.")
            show_login()
    else:
        show_login()
else:
    show_main_app(st.session_state["user_email"])

