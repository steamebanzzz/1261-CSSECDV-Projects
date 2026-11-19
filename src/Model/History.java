package Model;

import java.math.BigDecimal;

public final class History {

    private final int id;
    private final int userId;
    private final int productId;
    private final String username;
    private final String name;
    private final int stock;
    private final Long unitPriceCents;
    private final String timestamp;

    public History(
            int id,
            int userId,
            int productId,
            String username,
            String name,
            int stock,
            Long unitPriceCents,
            String timestamp) {

        this.id = id;
        this.userId = userId;
        this.productId = productId;
        this.username = username;
        this.name = name;
        this.stock = stock;
        this.unitPriceCents = unitPriceCents;
        this.timestamp = timestamp;
    }

    public int getId() {
        return id;
    }

    public int getUserId() {
        return userId;
    }

    public int getProductId() {
        return productId;
    }

    public String getUsername() {
        return username;
    }

    public String getName() {
        return name;
    }

    public int getStock() {
        return stock;
    }

    public Long getUnitPriceCents() {
        return unitPriceCents;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public BigDecimal getPrice() {
        return unitPriceCents == null
                ? null : BigDecimal.valueOf(unitPriceCents, 2);
    }

    public BigDecimal getTotal() {
        return getPrice() == null
                ? null : getPrice().multiply(BigDecimal.valueOf(stock));
    }
}