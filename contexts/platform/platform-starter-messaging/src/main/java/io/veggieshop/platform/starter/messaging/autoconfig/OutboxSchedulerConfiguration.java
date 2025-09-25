package io.veggieshop.platform.starter.messaging.autoconfig;

import io.veggieshop.platform.messaging.outbox.OutboxPublisher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ScheduledFuture;

@AutoConfiguration
@ConditionalOnProperty(prefix = "veggieshop.outbox.scheduler", name = "enabled", havingValue = "true", matchIfMissing = true)
public class OutboxSchedulerConfiguration {

    @Bean
    TaskScheduler outboxTaskScheduler() {
        ThreadPoolTaskScheduler s = new ThreadPoolTaskScheduler();
        s.setPoolSize(1);
        s.setThreadNamePrefix("outbox-drain-");
        s.initialize();
        return s;
    }

    @Bean
    ScheduledFuture<?> outboxDrainLoop(TaskScheduler scheduler,
                                       OutboxPublisher outbox,
                                       VeggieOutboxProperties p) {

        Duration initial = p.getScheduler().getInitialDelay();
        Duration interval = p.getScheduler().getInterval();
        int burst = p.getScheduler().getBurstBatches();
        Duration maxBurst = p.getScheduler().getMaxBurstDuration();
        Duration idleSleep = p.getScheduler().getIdleSleep();

        // استخدم التوقيع: scheduleWithFixedDelay(Runnable, Instant startTime, Duration delay)
        return scheduler.scheduleWithFixedDelay(() -> {
            long start = System.nanoTime();
            int done = 0;
            while (done < burst && (System.nanoTime() - start) < maxBurst.toNanos()) {
                try {
                    outbox.drainOnce();
                    done++;
                } catch (Exception e) {
                    // يمكن إضافة عدّادات/سجلات هنا عند الحاجة
                    break;
                }
            }
            if (done == 0) {
                // لا backlog؟ نم قليلًا لتقليل الضغط
                try { Thread.sleep(idleSleep.toMillis()); }
                catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }
        }, Instant.now().plus(initial), interval);
    }
}
