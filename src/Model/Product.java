/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Model;

import java.math.BigDecimal;

public final class Product {

    private final int id;
    private final String name;
    private final int stock;
    private final long priceCents;

    public Product(int id, String name, int stock, long priceCents) {
        this.id = id;
        this.name = name;
        this.stock = stock;
        this.priceCents = priceCents;
    }

    public int getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public int getStock() {
        return stock;
    }

    public long getPriceCents() {
        return priceCents;
    }

    public BigDecimal getPrice() {
        return BigDecimal.valueOf(priceCents, 2);
    }
}