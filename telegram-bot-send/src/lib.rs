use log::warn;
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

pub struct TelegramBotBuilder {
    pub bot_token: String,
    pub http_proxy: Option<String>,
}

impl TelegramBotBuilder {
    pub fn new(bot_token: String) -> Self {
        TelegramBotBuilder {
            bot_token,
            http_proxy: None,
        }
    }

    pub fn http_proxy(mut self, proxy: String) -> Self {
        self.http_proxy = Some(proxy);
        self
    }

    pub fn build(self) -> Result<TelegramBot, DynError> {
        let mut builder = Client::builder().pool_max_idle_per_host(10);
        if let Some(proxy_url) = &self.http_proxy {
            builder = builder.proxy(Proxy::all(proxy_url)?);
        }
        let client = builder.build()?;
        Ok(TelegramBot {
            client,
            bot_token: self.bot_token,
        })
    }
}

pub struct TelegramBot {
    pub client: Client,
    pub bot_token: String,
}

impl TelegramBot {
    pub async fn send_message(&self, chat_id: String, message: String) -> Result<(), DynError> {
        let url = format!("https://api.telegram.org/{}/sendMessage", &self.bot_token);
        let tele_msg = TelegramMessage::new(chat_id.clone(), message);
        let msg = serde_json::to_string(&tele_msg)?;
        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json; charset=utf-8")
            .body(msg.clone())
            .send()
            .await?;
        let text = resp.text().await?;
        let send_result: TGSendResult = serde_json::from_str(&text)?;
        if !send_result.ok {
            warn!("send message error: {text}, req is: {msg}, url is {url}");
            return Err(format!("send message error: {}", send_result.description.unwrap_or_default()).into());
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
struct TGSendResult {
    pub(crate) ok: bool,
    pub(crate) description: Option<String>,
}

/// 格式化所有特殊字符为 MarkdownV2 格式
pub fn format_md2_all(text: &str) -> String {
    text.replace(r"\", r"\\")
        .replace("_", r"\_")
        .replace("*", r"\*")
        .replace("[", r"\[")
        .replace("]", r"\]")
        .replace("(", r"\(")
        .replace(")", r"\)")
        .replace("~", r"\~")
        .replace("`", r"\`")
        .replace(">", r"\>")
        .replace("#", r"\#")
        .replace("+", r"\+")
        .replace("-", r"\-")
        .replace("=", r"\=")
        .replace("|", r"\|")
        .replace("{", r"\{")
        .replace("}", r"\}")
        .replace(".", r"\.")
        .replace("!", r"\!")
}

/// 格式化 URL 为 MarkdownV2 格式
pub fn format_md2_url(url: &str) -> String {
    url.replace(r"\", r"\\").replace(")", r"\)")
}

/// 格式化代码块为 MarkdownV2 格式
pub fn format_md2_pre_code(code: &str) -> String {
    code.replace(r"\", r"\\").replace("`", r"\`")
}

#[derive(serde::Serialize)]
struct TelegramMessage {
    chat_id: String,
    text: String,
    parse_mode: String,
}

impl TelegramMessage {
    fn new(chat_id: String, text: String) -> Self {
        TelegramMessage {
            chat_id,
            text,
            parse_mode: "MarkdownV2".to_string(),
        }
    }
}
