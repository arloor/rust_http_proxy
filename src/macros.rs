macro_rules! serve_with_idle_timeout {
    ($io:ident,$proxy_handler:ident,$config:ident,$client_socket_addr:ident) => {
        let binding =auto::Builder::new(hyper_util::rt::tokio::TokioExecutor::new());
        let context=Arc::new(RwLock::new(Context::default()));
        let context_c=context.clone();
        let connection =
            binding.serve_connection_with_upgrades($io, service_fn(move |req| {
                proxy(
                    req,
                    $config,
                    $client_socket_addr,
                    $proxy_handler.clone(),
                    context.clone()
                )
            }));
        tokio::pin!(connection);
        loop {
            let upgraded;
            let last_instant;
            {
                let context = context_c.read().unwrap();
                upgraded = context.upgraded;
                last_instant = context.instant;
            }
            if upgraded {
                tokio::select! {
                    res = connection.as_mut() => {
                        if let Err(err)=res{
                            handle_hyper_error($client_socket_addr,err);
                        }
                        break;
                    }
                }
            } else {
                tokio::select! {
                    res = connection.as_mut() => {
                        if let Err(err)=res{
                            handle_hyper_error($client_socket_addr,err);
                        }
                        break;
                    }
                    _ = tokio::time::sleep_until(last_instant+Duration::from_secs(IDLE_SECONDS)) => {
                        let upgraded;
                        let instant;
                        {
                            let context = context_c.read().unwrap();
                            upgraded = context.upgraded;
                            instant = context.instant;
                        }
                        if upgraded {
                            continue;
                        }else if instant <= last_instant {
                            info!("idle for {} seconds, graceful_shutdown [{}]",IDLE_SECONDS,$client_socket_addr);
                            connection.as_mut().graceful_shutdown();
                            break;
                        }
                    }
                }
            }
        }
    };
}
